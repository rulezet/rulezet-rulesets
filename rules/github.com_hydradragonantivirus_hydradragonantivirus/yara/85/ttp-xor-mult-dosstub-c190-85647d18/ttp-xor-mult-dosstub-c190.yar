rule TTP_XOR_MULT_DOSStub_c190 {
  strings:
    $key_c190 = { 95 f8 [2] e1 e0 [2] a6 e2 [2] e1 f3 [2] af ff [2] a3 f5 [2] b4 fe [2] af b0 [2] 92 }

  condition:
    any of them
}