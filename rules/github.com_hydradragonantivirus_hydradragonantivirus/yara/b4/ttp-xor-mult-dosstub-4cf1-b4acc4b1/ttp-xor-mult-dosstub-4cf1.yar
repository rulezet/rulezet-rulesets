rule TTP_XOR_MULT_DOSStub_4cf1 {
  strings:
    $key_4cf1 = { 18 99 [2] 6c 81 [2] 2b 83 [2] 6c 92 [2] 22 9e [2] 2e 94 [2] 39 9f [2] 22 d1 [2] 1f }

  condition:
    any of them
}