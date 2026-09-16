rule TTP_XOR_MULT_DOSStub_4657 {
  strings:
    $key_4657 = { 12 3f [2] 66 27 [2] 21 25 [2] 66 34 [2] 28 38 [2] 24 32 [2] 33 39 [2] 28 77 [2] 15 }

  condition:
    any of them
}