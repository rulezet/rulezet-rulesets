rule TTP_XOR_MULT_DOSStub_e9c8 {
  strings:
    $key_e9c8 = { bd a0 [2] c9 b8 [2] 8e ba [2] c9 ab [2] 87 a7 [2] 8b ad [2] 9c a6 [2] 87 e8 [2] ba }

  condition:
    any of them
}