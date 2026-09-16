rule TTP_XOR_MULT_DOSStub_5ccb {
  strings:
    $key_5ccb = { 08 a3 [2] 7c bb [2] 3b b9 [2] 7c a8 [2] 32 a4 [2] 3e ae [2] 29 a5 [2] 32 eb [2] 0f }

  condition:
    any of them
}