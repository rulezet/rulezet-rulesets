rule TTP_XOR_MULT_DOSStub_7027 {
  strings:
    $key_7027 = { 24 4f [2] 50 57 [2] 17 55 [2] 50 44 [2] 1e 48 [2] 12 42 [2] 05 49 [2] 1e 07 [2] 23 }

  condition:
    any of them
}