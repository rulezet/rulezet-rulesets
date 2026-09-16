rule TTP_XOR_MULT_DOSStub_c196 {
  strings:
    $key_c196 = { 95 fe [2] e1 e6 [2] a6 e4 [2] e1 f5 [2] af f9 [2] a3 f3 [2] b4 f8 [2] af b6 [2] 92 }

  condition:
    any of them
}