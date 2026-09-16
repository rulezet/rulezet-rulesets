rule TTP_XOR_MULT_DOSStub_5837 {
  strings:
    $key_5837 = { 0c 5f [2] 78 47 [2] 3f 45 [2] 78 54 [2] 36 58 [2] 3a 52 [2] 2d 59 [2] 36 17 [2] 0b }

  condition:
    any of them
}