rule libavcodec_COOK_ccpl_huffcodes6__16_lil_126_ {
  strings:
    $a0 = { 04 00 05 00 05 00 06 00 06 00 07 00 07 00 07 00 07 00 08 00 08 00 08 00 08 00 09 00 09 00 09 00 09 00 0a 00 0a 00 0a 00 0a 00 0a 00 0b 00 0b 00 0b 00 0b 00 0c 00 0d 00 0e 00 0e 00 10 00 00 00 0a 00 18 00 19 00 36 00 37 00 74 00 75 00 76 00 77 00 f4 00 f5 00 f6 00 f7 00 f5 01 f6 01 f7 01 f8 01 f6 03 f7 03 f8 03 f9 03 fa 03 fa 07 fb 07 fc 07 fd 07 fd 0f fd 1f fd 3f fe 3f ff ff }

  condition:
    $a0
}