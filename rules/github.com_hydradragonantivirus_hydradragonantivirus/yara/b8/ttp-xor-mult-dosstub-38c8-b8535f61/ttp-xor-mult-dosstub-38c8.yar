rule TTP_XOR_MULT_DOSStub_38c8 {
  strings:
    $key_38c8 = { 6c a0 [2] 18 b8 [2] 5f ba [2] 18 ab [2] 56 a7 [2] 5a ad [2] 4d a6 [2] 56 e8 [2] 6b }

  condition:
    any of them
}