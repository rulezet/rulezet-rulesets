rule TTP_XOR_MULT_DOSStub_1ccb {
  strings:
    $key_1ccb = { 48 a3 [2] 3c bb [2] 7b b9 [2] 3c a8 [2] 72 a4 [2] 7e ae [2] 69 a5 [2] 72 eb [2] 4f }

  condition:
    any of them
}