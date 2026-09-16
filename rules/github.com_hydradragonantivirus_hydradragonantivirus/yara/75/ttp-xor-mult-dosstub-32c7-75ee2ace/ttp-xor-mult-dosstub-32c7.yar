rule TTP_XOR_MULT_DOSStub_32c7 {
  strings:
    $key_32c7 = { 66 af [2] 12 b7 [2] 55 b5 [2] 12 a4 [2] 5c a8 [2] 50 a2 [2] 47 a9 [2] 5c e7 [2] 61 }

  condition:
    any of them
}