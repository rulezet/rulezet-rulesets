rule TTP_XOR_MULT_DOSStub_7850 {
  strings:
    $key_7850 = { 2c 38 [2] 58 20 [2] 1f 22 [2] 58 33 [2] 16 3f [2] 1a 35 [2] 0d 3e [2] 16 70 [2] 2b }

  condition:
    any of them
}