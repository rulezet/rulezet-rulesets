rule TTP_XOR_MULT_DOSStub_2ace {
  strings:
    $key_2ace = { 7e a6 [2] 0a be [2] 4d bc [2] 0a ad [2] 44 a1 [2] 48 ab [2] 5f a0 [2] 44 ee [2] 79 }

  condition:
    any of them
}