rule libavcodec_ff_svq1_frame_size_table__16_lil_32_ {
  strings:
    $a0 = { A0 00 78 00 80 00 60 00 B0 00 90 00 60 01 20 01 C0 02 40 02 F0 00 B4 00 40 01 F0 00 FF FF FF FF }

  condition:
    $a0
}