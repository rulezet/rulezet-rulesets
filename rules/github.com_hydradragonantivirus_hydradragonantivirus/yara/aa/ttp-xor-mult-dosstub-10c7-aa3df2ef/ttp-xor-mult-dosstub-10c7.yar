rule TTP_XOR_MULT_DOSStub_10c7 {
  strings:
    $key_10c7 = { 44 af [2] 30 b7 [2] 77 b5 [2] 30 a4 [2] 7e a8 [2] 72 a2 [2] 65 a9 [2] 7e e7 [2] 43 }

  condition:
    any of them
}