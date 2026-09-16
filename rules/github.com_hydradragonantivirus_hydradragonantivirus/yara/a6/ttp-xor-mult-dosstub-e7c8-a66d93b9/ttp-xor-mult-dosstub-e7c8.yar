rule TTP_XOR_MULT_DOSStub_e7c8 {
  strings:
    $key_e7c8 = { b3 a0 [2] c7 b8 [2] 80 ba [2] c7 ab [2] 89 a7 [2] 85 ad [2] 92 a6 [2] 89 e8 [2] b4 }

  condition:
    any of them
}