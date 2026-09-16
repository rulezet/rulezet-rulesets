rule _20160921_3e524aa8d0a18c87370a789c7bba4fc5_20160921_e949fdc198fe_1477 {
  meta:
    description = "datamaliciousorder - from files 20160921_3e524aa8d0a18c87370a789c7bba4fc5.js, 20160921_e949fdc198fee477717395093f5853e7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71a83b86275cb43222066a6d27dfb98cdd9fc8283b2b007f9262c38686262b9a"
    hash2       = "4ff56149c45e72e300c579a750f7d49b8e0e723f75bb7a74343267578dd71a4d"

  strings:
    $s1  = "DYs\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"TRc\";})(),(functio" ascii
    $s2  = "{return \"OUx\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";}" ascii
    $s3  = "return \"MMz\";})(),(function f000(){return \"MKa\";})()];" fullword ascii
    $s4  = "ction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){retur" ascii
    $s5  = "000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"SGs" ascii
    $s6  = "rn \"Br\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(fu" ascii
    $s7  = "\"OUx\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s8  = "ction f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){retur" ascii
    $s9  = "on f000(){return \"OUx\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"SGs\";})(),(function f000(){return " ascii
    $s10 = "00(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Tn\"" ascii
    $s11 = "){return \"QDg\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"QDg\";}" ascii
    $s12 = "rn \"Uo\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s13 = "n \"ZGq\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}