rule TTP_XOR_MULT_DOSStub_c2ca {
  strings:
    $key_c2ca = { 96 a2 [2] e2 ba [2] a5 b8 [2] e2 a9 [2] ac a5 [2] a0 af [2] b7 a4 [2] ac ea [2] 91 }

  condition:
    any of them
}