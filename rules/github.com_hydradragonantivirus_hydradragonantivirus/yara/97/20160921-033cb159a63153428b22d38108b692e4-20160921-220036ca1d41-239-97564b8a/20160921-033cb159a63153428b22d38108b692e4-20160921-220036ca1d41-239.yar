rule _20160921_033cb159a63153428b22d38108b692e4_20160921_220036ca1d41_239 {
  meta:
    description = "datamaliciousorder - from files 20160921_033cb159a63153428b22d38108b692e4.js, 20160921_220036ca1d4152e6bd72a833a4b3f832.js, 20160921_b2c7637ff56cbf278f1a457ae1833df9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d370303fc83ddc3470e00cb54841641f9f338c2f025096e84d40782778041a8b"
    hash2       = "54f3e02c5b6d4d5d2db9a8d86252256d2f355ce582a09c9d870f84a9047c47ff"
    hash3       = "a19789bb6f28d27bc82c039f4db69fb5cc4c189a7a47cddfffcdc6eace37a408"

  strings:
    $s1  = "\"IAa\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(func" ascii
    $s2  = "DYx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(funct" ascii
    $s3  = "rn \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"XTn\";})(),(" ascii
    $s4  = "rn \"Br\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Iq\";})(),(fun" ascii
    $s5  = "),(function f000(){return \"Vu\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"IPu\";})(),(function f000(){" ascii
    $s6  = "eturn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Nv\";})(),(" ascii
    $s7  = ")(),(function f000(){return \"Vu\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"DNa\";})(),(function f000(" ascii
    $s8  = "(){return \"Ml\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Br\";})(" ascii
    $s9  = "000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn" ascii
    $s10 = "rn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Rh\";})(),(fun" ascii
    $s11 = "\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"DYx\";})(),(function " ascii
    $s12 = "00(){return \"Br\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Vu\";" ascii
    $s13 = "){return \"Br\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Br\";})(" ascii
    $s14 = "(function f000(){return \"OUx\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Mt\";})(),(function f000(){r" ascii
    $s15 = "ction f000(){return \"Br\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"UEg\";})(),(function f000(){return" ascii
    $s16 = "unction f000(){return \"DAp\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"ZIi\";})(),(function f000(){ret" ascii
    $s17 = "TKl\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s18 = "turn \"Br\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s19 = "on f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return " ascii
    $s20 = "n \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Vj\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}