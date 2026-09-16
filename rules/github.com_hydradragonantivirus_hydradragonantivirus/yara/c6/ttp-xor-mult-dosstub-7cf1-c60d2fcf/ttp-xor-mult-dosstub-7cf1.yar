rule TTP_XOR_MULT_DOSStub_7cf1 {
  strings:
    $key_7cf1 = { 28 99 [2] 5c 81 [2] 1b 83 [2] 5c 92 [2] 12 9e [2] 1e 94 [2] 09 9f [2] 12 d1 [2] 2f }

  condition:
    any of them
}