rule libmpdvdkit2_css_p_variants__8_byt_32_ {
  strings:
    $a0 = { b7 74 85 d0 cc db ca 73 03 fe 31 03 52 e0 b7 42 63 16 f2 2a 79 52 ff 1b 7a 11 ca 1a 9b 40 ad 01 }

  condition:
    $a0
}