rule TTP_XOR_MULT_DOSStub_c185 {
  strings:
    $key_c185 = { 95 ed [2] e1 f5 [2] a6 f7 [2] e1 e6 [2] af ea [2] a3 e0 [2] b4 eb [2] af a5 [2] 92 }

  condition:
    any of them
}