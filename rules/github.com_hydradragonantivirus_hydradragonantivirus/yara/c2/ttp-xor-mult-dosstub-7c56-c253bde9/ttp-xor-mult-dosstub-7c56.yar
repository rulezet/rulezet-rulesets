rule TTP_XOR_MULT_DOSStub_7c56 {
  strings:
    $key_7c56 = { 28 3e [2] 5c 26 [2] 1b 24 [2] 5c 35 [2] 12 39 [2] 1e 33 [2] 09 38 [2] 12 76 [2] 2f }

  condition:
    any of them
}