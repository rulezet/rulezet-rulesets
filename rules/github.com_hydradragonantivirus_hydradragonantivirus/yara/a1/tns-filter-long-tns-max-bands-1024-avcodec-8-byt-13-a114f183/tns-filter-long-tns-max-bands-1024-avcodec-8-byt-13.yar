rule TNS_filter_long_tns_max_bands_1024__avcodec___8_byt_13_ {
  strings:
    $a0 = { 1f 1f 22 28 2a 33 2e 2e 2a 2a 2a 27 27 }

  condition:
    $a0
}