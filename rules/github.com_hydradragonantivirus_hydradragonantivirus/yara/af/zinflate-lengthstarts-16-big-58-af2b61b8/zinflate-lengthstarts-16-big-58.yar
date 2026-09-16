rule zinflate_lengthStarts__16_big_58_ {
  strings:
    $a0 = { 00 03 00 04 00 05 00 06 00 07 00 08 00 09 00 0a 00 0b 00 0d 00 0f 00 11 00 13 00 17 00 1b 00 1f 00 23 00 2b 00 33 00 3b 00 43 00 53 00 63 00 73 00 83 00 a3 00 c3 00 e3 01 02 }

  condition:
    $a0
}