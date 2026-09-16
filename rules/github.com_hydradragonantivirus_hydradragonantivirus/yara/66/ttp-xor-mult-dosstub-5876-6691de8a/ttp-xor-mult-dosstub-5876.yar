rule TTP_XOR_MULT_DOSStub_5876 {
  strings:
    $key_5876 = { 0c 1e [2] 78 06 [2] 3f 04 [2] 78 15 [2] 36 19 [2] 3a 13 [2] 2d 18 [2] 36 56 [2] 0b }

  condition:
    any of them
}