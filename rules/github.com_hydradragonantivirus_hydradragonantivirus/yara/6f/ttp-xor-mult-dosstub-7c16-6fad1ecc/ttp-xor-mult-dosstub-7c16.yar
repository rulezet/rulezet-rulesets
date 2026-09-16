rule TTP_XOR_MULT_DOSStub_7c16 {
  strings:
    $key_7c16 = { 28 7e [2] 5c 66 [2] 1b 64 [2] 5c 75 [2] 12 79 [2] 1e 73 [2] 09 78 [2] 12 36 [2] 2f }

  condition:
    any of them
}