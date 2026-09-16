rule TTP_XOR_MULT_DOSStub_7ccb {
  strings:
    $key_7ccb = { 28 a3 [2] 5c bb [2] 1b b9 [2] 5c a8 [2] 12 a4 [2] 1e ae [2] 09 a5 [2] 12 eb [2] 2f }

  condition:
    any of them
}