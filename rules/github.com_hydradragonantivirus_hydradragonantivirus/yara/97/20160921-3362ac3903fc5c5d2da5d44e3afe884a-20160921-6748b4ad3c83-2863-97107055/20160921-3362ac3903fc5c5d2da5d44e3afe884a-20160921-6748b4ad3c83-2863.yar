rule _20160921_3362ac3903fc5c5d2da5d44e3afe884a_20160921_6748b4ad3c83_2863 {
  meta:
    description = "datamaliciousorder - from files 20160921_3362ac3903fc5c5d2da5d44e3afe884a.js, 20160921_6748b4ad3c83a7c4aeacfc0817a81797.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "923e3ebc3e8bab3120c507f019cac28dec05009a69ab441bfb8be6f7f1a4d258"
    hash2       = "f5e85f2791984d17e00bdb2b7163597d52bf88d9da5a0caedc977a31026ee9f7"

  strings:
    $s1 = "function f000(){return \"WIj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){re" ascii
    $s2 = "){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"RVb\";" ascii
    $s3 = "ion f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return " ascii
    $s4 = ",(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"MJq\";})(),(function f000()" ascii
    $s5 = "n \"TKl\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Go\";})(),(fu" ascii
    $s6 = "Oe\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(functio" ascii
    $s7 = "000(){return \"Vu\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}