rule libavcodec_VC_1_and_WMV3_dcpred__16_big_64_ {
  strings:
    $a0 = { FF FF 04 00 02 00 01 55 01 00 00 CD 00 AB 00 92 00 80 00 72 00 66 00 5D 00 55 00 4F 00 49 00 44 00 40 00 3C 00 39 00 36 00 33 00 31 00 2F 00 2D 00 2B 00 29 00 27 00 26 00 25 00 23 00 22 00 21 }

  condition:
    $a0
}