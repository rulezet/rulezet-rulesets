rule _20160921_06b8a8ba37bdbe66227238ed6343de45_20160921_37b52e41aabc_4279 {
  meta:
    description = "datamaliciousorder - from files 20160921_06b8a8ba37bdbe66227238ed6343de45.js, 20160921_37b52e41aabc93218d864c1665a33610.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49865219ca3278a1a02bfd25fc25cac90e7685a0b5083a98acee0c82fc74d77b"
    hash2       = "c506490b3737e1b21522717204e4143ada427e9af58fe86e42ed31dfd0fde66a"

  strings:
    $s1 = "tion f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return" ascii
    $s2 = "})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f00" ascii
    $s3 = "n f000(){return \"Ml\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Yz" ascii
    $s4 = "(function f000(){return \"YTp\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"UEg\";})(),(function f000(){r" ascii
    $s5 = "\"Wy\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Oe\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}