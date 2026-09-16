rule LOKI97_values__32_big_AND_ {
  strings:
    $a0 = { 00 00 29 11 [0-20] 00 00 20 00 [0-20] 00 00 0a a7 [0-20] 00 00 08 00 [0-20] 9e 37 79 b9 [0-20] 7f 4a 7c 15 }

  condition:
    $a0
}