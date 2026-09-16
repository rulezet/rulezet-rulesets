rule TTP_XOR_MULT_DOSStub_3ccb {
  strings:
    $key_3ccb = { 68 a3 [2] 1c bb [2] 5b b9 [2] 1c a8 [2] 52 a4 [2] 5e ae [2] 49 a5 [2] 52 eb [2] 6f }

  condition:
    any of them
}