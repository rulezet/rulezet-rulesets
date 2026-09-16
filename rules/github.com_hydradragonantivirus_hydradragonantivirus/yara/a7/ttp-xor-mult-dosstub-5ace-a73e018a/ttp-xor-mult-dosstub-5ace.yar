rule TTP_XOR_MULT_DOSStub_5ace {
  strings:
    $key_5ace = { 0e a6 [2] 7a be [2] 3d bc [2] 7a ad [2] 34 a1 [2] 38 ab [2] 2f a0 [2] 34 ee [2] 09 }

  condition:
    any of them
}