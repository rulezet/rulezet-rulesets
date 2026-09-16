rule TTP_XOR_MULT_DOSStub_c5ce {
  strings:
    $key_c5ce = { 91 a6 [2] e5 be [2] a2 bc [2] e5 ad [2] ab a1 [2] a7 ab [2] b0 a0 [2] ab ee [2] 96 }

  condition:
    any of them
}