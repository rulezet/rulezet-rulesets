rule TTP_XOR_MULT_DOSStub_7057 {
  strings:
    $key_7057 = { 24 3f [2] 50 27 [2] 17 25 [2] 50 34 [2] 1e 38 [2] 12 32 [2] 05 39 [2] 1e 77 [2] 23 }

  condition:
    any of them
}