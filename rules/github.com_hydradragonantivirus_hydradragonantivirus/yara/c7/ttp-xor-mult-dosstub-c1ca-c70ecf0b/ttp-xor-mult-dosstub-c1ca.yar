rule TTP_XOR_MULT_DOSStub_c1ca {
  strings:
    $key_c1ca = { 95 a2 [2] e1 ba [2] a6 b8 [2] e1 a9 [2] af a5 [2] a3 af [2] b4 a4 [2] af ea [2] 92 }

  condition:
    any of them
}