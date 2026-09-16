rule libavcodec_intrax8_crazy_mix_runlevel__8_byt_32_ {
  strings:
    $a0 = { 22 32 33 53 23 42 43 63 24 52 34 73 25 62 44 83 26 72 35 54 27 82 45 64 28 92 36 74 29 a2 46 84 }

  condition:
    $a0
}