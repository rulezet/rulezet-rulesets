rule TTP_XOR_MULT_DOSStub_c1ce {
  strings:
    $key_c1ce = { 95 a6 [2] e1 be [2] a6 bc [2] e1 ad [2] af a1 [2] a3 ab [2] b4 a0 [2] af ee [2] 92 }

  condition:
    any of them
}