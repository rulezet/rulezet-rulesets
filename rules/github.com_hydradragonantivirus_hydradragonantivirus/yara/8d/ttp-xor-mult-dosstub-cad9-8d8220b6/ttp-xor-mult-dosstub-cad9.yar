rule TTP_XOR_MULT_DOSStub_cad9 {
  strings:
    $key_cad9 = { 9e b1 [2] ea a9 [2] ad ab [2] ea ba [2] a4 b6 [2] a8 bc [2] bf b7 [2] a4 f9 [2] 99 }

  condition:
    any of them
}