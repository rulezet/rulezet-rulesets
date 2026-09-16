rule TTP_XOR_MULT_DOSStub_c593 {
  strings:
    $key_c593 = { 91 fb [2] e5 e3 [2] a2 e1 [2] e5 f0 [2] ab fc [2] a7 f6 [2] b0 fd [2] ab b3 [2] 96 }

  condition:
    any of them
}