rule TTP_XOR_MULT_DOSStub_7040 {
  strings:
    $key_7040 = { 24 28 [2] 50 30 [2] 17 32 [2] 50 23 [2] 1e 2f [2] 12 25 [2] 05 2e [2] 1e 60 [2] 23 }

  condition:
    any of them
}