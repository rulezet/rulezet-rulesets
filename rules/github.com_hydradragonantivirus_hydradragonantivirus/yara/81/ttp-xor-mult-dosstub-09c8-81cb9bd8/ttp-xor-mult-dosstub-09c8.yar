rule TTP_XOR_MULT_DOSStub_09c8 {
  strings:
    $key_09c8 = { 5d a0 [2] 29 b8 [2] 6e ba [2] 29 ab [2] 67 a7 [2] 6b ad [2] 7c a6 [2] 67 e8 [2] 5a }

  condition:
    any of them
}