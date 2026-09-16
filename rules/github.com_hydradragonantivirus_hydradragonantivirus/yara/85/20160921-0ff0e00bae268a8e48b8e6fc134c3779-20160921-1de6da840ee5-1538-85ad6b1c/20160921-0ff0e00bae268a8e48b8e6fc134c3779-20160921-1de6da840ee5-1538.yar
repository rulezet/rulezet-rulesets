rule _20160921_0ff0e00bae268a8e48b8e6fc134c3779_20160921_1de6da840ee5_1538 {
  meta:
    description = "datamaliciousorder - from files 20160921_0ff0e00bae268a8e48b8e6fc134c3779.js, 20160921_1de6da840ee50be73263cde38bfe05f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f9f30b45066ff23899a854b2ef766240b2becea05223ad11c6bf5cde97c3048"
    hash2       = "28c58fd3e89dda2f745d131d428bf5c447e7f5e2bdee82bb72c417d8a0be878a"

  strings:
    $s1  = "(function f000(){return \"Do\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){re" ascii
    $s2  = "(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";" ascii
    $s3  = "on f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"" ascii
    $s4  = "ion f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(function f000(){return " ascii
    $s5  = " \"Lp\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s6  = "000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Yi\"" ascii
    $s7  = "(function f000(){return \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){r" ascii
    $s8  = "unction f000(){return \"Do\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){ret" ascii
    $s9  = "rn \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(f" ascii
    $s10 = "function f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"DIa\";})(),(function f000(){re" ascii
    $s11 = "{return \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Fs\";})(" ascii
    $s12 = " \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}