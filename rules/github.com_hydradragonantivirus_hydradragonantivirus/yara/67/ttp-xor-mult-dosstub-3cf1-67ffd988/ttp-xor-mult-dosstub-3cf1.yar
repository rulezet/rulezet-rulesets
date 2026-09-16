rule TTP_XOR_MULT_DOSStub_3cf1 {
  strings:
    $key_3cf1 = { 68 99 [2] 1c 81 [2] 5b 83 [2] 1c 92 [2] 52 9e [2] 5e 94 [2] 49 9f [2] 52 d1 [2] 6f }

  condition:
    any of them
}