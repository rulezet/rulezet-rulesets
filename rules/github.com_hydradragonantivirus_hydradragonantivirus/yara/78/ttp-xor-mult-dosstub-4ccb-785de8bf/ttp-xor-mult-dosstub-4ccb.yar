rule TTP_XOR_MULT_DOSStub_4ccb {
  strings:
    $key_4ccb = { 18 a3 [2] 6c bb [2] 2b b9 [2] 6c a8 [2] 22 a4 [2] 2e ae [2] 39 a5 [2] 22 eb [2] 1f }

  condition:
    any of them
}