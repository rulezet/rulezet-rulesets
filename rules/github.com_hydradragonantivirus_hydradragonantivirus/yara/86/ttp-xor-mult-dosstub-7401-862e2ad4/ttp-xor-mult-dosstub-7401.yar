rule TTP_XOR_MULT_DOSStub_7401 {
  strings:
    $key_7401 = { 20 69 [2] 54 71 [2] 13 73 [2] 54 62 [2] 1a 6e [2] 16 64 [2] 01 6f [2] 1a 21 [2] 27 }

  condition:
    any of them
}