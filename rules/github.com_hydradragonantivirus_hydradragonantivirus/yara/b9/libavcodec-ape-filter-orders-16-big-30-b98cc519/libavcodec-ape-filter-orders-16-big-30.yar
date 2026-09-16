rule libavcodec_ape_filter_orders__16_big_30_ {
  strings:
    $a0 = { 00 00 00 00 00 00 00 10 00 00 00 00 00 40 00 00 00 00 00 20 01 00 00 00 00 10 01 00 05 00 }

  condition:
    $a0
}