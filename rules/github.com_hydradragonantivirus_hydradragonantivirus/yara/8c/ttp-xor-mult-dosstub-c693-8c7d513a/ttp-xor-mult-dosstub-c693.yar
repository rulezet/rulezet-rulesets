rule TTP_XOR_MULT_DOSStub_c693 {
  strings:
    $key_c693 = { 92 fb [2] e6 e3 [2] a1 e1 [2] e6 f0 [2] a8 fc [2] a4 f6 [2] b3 fd [2] a8 b3 [2] 95 }

  condition:
    any of them
}