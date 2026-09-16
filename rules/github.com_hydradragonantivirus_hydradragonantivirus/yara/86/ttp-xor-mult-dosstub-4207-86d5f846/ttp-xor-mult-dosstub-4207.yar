rule TTP_XOR_MULT_DOSStub_4207 {
  strings:
    $key_4207 = { 16 6f [2] 62 77 [2] 25 75 [2] 62 64 [2] 2c 68 [2] 20 62 [2] 37 69 [2] 2c 27 [2] 11 }

  condition:
    any of them
}