rule TTP_XOR_MULT_DOSStub_f9c8 {
  strings:
    $key_f9c8 = { ad a0 [2] d9 b8 [2] 9e ba [2] d9 ab [2] 97 a7 [2] 9b ad [2] 8c a6 [2] 97 e8 [2] aa }

  condition:
    any of them
}