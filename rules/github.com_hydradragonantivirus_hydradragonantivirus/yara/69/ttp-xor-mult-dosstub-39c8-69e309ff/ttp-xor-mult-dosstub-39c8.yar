rule TTP_XOR_MULT_DOSStub_39c8 {
  strings:
    $key_39c8 = { 6d a0 [2] 19 b8 [2] 5e ba [2] 19 ab [2] 57 a7 [2] 5b ad [2] 4c a6 [2] 57 e8 [2] 6a }

  condition:
    any of them
}