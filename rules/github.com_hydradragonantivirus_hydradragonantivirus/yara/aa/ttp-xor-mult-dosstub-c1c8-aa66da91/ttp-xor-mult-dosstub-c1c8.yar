rule TTP_XOR_MULT_DOSStub_c1c8 {
  strings:
    $key_c1c8 = { 95 a0 [2] e1 b8 [2] a6 ba [2] e1 ab [2] af a7 [2] a3 ad [2] b4 a6 [2] af e8 [2] 92 }

  condition:
    any of them
}