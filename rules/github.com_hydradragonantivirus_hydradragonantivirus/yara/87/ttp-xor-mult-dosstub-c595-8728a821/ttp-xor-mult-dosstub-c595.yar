rule TTP_XOR_MULT_DOSStub_c595 {
  strings:
    $key_c595 = { 91 fd [2] e5 e5 [2] a2 e7 [2] e5 f6 [2] ab fa [2] a7 f0 [2] b0 fb [2] ab b5 [2] 96 }

  condition:
    any of them
}