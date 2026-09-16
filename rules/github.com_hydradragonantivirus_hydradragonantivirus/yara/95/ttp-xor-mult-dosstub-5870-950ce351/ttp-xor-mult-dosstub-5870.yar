rule TTP_XOR_MULT_DOSStub_5870 {
  strings:
    $key_5870 = { 0c 18 [2] 78 00 [2] 3f 02 [2] 78 13 [2] 36 1f [2] 3a 15 [2] 2d 1e [2] 36 50 [2] 0b }

  condition:
    any of them
}