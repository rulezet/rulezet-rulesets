rule TTP_XOR_MULT_DOSStub_c398 {
  strings:
    $key_c398 = { 97 f0 [2] e3 e8 [2] a4 ea [2] e3 fb [2] ad f7 [2] a1 fd [2] b6 f6 [2] ad b8 [2] 90 }

  condition:
    any of them
}