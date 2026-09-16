rule TTP_XOR_MULT_DOSStub_e7d4 {
  strings:
    $key_e7d4 = { b3 bc [2] c7 a4 [2] 80 a6 [2] c7 b7 [2] 89 bb [2] 85 b1 [2] 92 ba [2] 89 f4 [2] b4 }

  condition:
    any of them
}