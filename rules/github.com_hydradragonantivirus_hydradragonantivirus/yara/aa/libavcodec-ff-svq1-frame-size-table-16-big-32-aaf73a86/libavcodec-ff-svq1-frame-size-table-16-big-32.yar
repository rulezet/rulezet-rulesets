rule libavcodec_ff_svq1_frame_size_table__16_big_32_ {
  strings:
    $a0 = { 00 A0 00 78 00 80 00 60 00 B0 00 90 01 60 01 20 02 C0 02 40 00 F0 00 B4 01 40 00 F0 FF FF FF FF }

  condition:
    $a0
}