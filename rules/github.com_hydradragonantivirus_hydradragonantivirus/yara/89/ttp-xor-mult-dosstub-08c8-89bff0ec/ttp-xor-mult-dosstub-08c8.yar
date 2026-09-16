rule TTP_XOR_MULT_DOSStub_08c8 {
  strings:
    $key_08c8 = { 5c a0 [2] 28 b8 [2] 6f ba [2] 28 ab [2] 66 a7 [2] 6a ad [2] 7d a6 [2] 66 e8 [2] 5b }

  condition:
    any of them
}