rule TTP_XOR_MULT_DOSStub_c3ce {
  strings:
    $key_c3ce = { 97 a6 [2] e3 be [2] a4 bc [2] e3 ad [2] ad a1 [2] a1 ab [2] b6 a0 [2] ad ee [2] 90 }

  condition:
    any of them
}