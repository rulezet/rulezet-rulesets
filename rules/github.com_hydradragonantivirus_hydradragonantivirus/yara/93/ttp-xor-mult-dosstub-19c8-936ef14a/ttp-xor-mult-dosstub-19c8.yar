rule TTP_XOR_MULT_DOSStub_19c8 {
  strings:
    $key_19c8 = { 4d a0 [2] 39 b8 [2] 7e ba [2] 39 ab [2] 77 a7 [2] 7b ad [2] 6c a6 [2] 77 e8 [2] 4a }

  condition:
    any of them
}