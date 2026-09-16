rule TTP_XOR_MULT_DOSStub_7870 {
  strings:
    $key_7870 = { 2c 18 [2] 58 00 [2] 1f 02 [2] 58 13 [2] 16 1f [2] 1a 15 [2] 0d 1e [2] 16 50 [2] 2b }

  condition:
    any of them
}