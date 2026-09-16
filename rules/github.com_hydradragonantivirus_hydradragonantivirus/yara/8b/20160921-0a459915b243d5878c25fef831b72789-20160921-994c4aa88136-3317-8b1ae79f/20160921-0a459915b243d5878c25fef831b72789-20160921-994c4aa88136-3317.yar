rule _20160921_0a459915b243d5878c25fef831b72789_20160921_994c4aa88136_3317 {
  meta:
    description = "datamaliciousorder - from files 20160921_0a459915b243d5878c25fef831b72789.js, 20160921_994c4aa8813658fbb0b792d8aa221e53.js, 20160922_7706788d60398ea7d883afb2532d218f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f8d1944044e8a67a527f50e4aeb45e9358929b0d0f7aaf1730d2782f07a09de"
    hash2       = "b7087906f833cc4e256e80f75293dfea38a9cf9102994a76779be7198f94535b"
    hash3       = "53ed2c9df290c888bf2af9ce5d017a8ed1c6b1bb1c82aa0376f1bc204aa27eb7"

  strings:
    $s1 = "){return \"Oh\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"ZGq\";})(" ascii
    $s2 = "\"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qj\";})(),(funct" ascii
    $s3 = "\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f" ascii
    $s4 = "(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Tn\";}" ascii
    $s5 = "0(){return \"Nv\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"KXg\";}" ascii
    $s6 = "{return \"HJm\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Yi\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}