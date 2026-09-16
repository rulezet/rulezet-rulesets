rule TTP_XOR_MULT_DOSStub_c6ca {
  strings:
    $key_c6ca = { 92 a2 [2] e6 ba [2] a1 b8 [2] e6 a9 [2] a8 a5 [2] a4 af [2] b3 a4 [2] a8 ea [2] 95 }

  condition:
    any of them
}