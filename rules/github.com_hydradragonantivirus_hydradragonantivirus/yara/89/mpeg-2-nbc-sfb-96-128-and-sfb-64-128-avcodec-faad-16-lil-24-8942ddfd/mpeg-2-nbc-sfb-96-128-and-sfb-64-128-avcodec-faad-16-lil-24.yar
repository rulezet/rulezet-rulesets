rule MPEG_2_NBC_sfb_96_128_and_sfb_64_128__avcodec___faad___16_lil_24_ {
  strings:
    $a0 = { 04 00 08 00 0c 00 10 00 14 00 18 00 20 00 28 00 30 00 40 00 5c 00 80 00 }

  condition:
    $a0
}