rule TTP_XOR_MULT_DOSStub_c395 {
  strings:
    $key_c395 = { 97 fd [2] e3 e5 [2] a4 e7 [2] e3 f6 [2] ad fa [2] a1 f0 [2] b6 fb [2] ad b5 [2] 90 }

  condition:
    any of them
}