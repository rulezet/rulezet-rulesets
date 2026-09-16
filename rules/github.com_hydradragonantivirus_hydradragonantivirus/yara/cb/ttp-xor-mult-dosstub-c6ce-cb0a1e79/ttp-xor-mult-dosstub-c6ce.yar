rule TTP_XOR_MULT_DOSStub_c6ce {
  strings:
    $key_c6ce = { 92 a6 [2] e6 be [2] a1 bc [2] e6 ad [2] a8 a1 [2] a4 ab [2] b3 a0 [2] a8 ee [2] 95 }

  condition:
    any of them
}