rule TTP_XOR_MULT_DOSStub_7017 {
  strings:
    $key_7017 = { 24 7f [2] 50 67 [2] 17 65 [2] 50 74 [2] 1e 78 [2] 12 72 [2] 05 79 [2] 1e 37 [2] 23 }

  condition:
    any of them
}