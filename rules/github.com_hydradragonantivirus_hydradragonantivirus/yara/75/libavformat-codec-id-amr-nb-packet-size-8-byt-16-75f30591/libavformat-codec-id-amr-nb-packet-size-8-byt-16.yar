rule libavformat_CODEC_ID_AMR_NB_packet_size__8_byt_16_ {
  strings:
    $a0 = { 0d 0e 10 12 14 15 1b 20 06 00 00 00 00 00 00 00 }

  condition:
    $a0
}