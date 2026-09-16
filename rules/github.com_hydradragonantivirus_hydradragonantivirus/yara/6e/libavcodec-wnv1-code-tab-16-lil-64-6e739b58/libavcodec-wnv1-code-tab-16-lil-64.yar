rule libavcodec_wnv1_code_tab__16_lil_64_ {
  strings:
    $a0 = { fd 01 09 00 fd 00 08 00 7d 00 07 00 3d 00 06 00 1d 00 05 00 0d 00 04 00 05 00 03 00 00 00 01 00 04 00 03 00 0c 00 04 00 1c 00 05 00 3c 00 06 00 7c 00 07 00 fc 00 08 00 fc 01 09 00 ff 00 08 00 }

  condition:
    $a0
}