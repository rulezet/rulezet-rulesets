rule TTP_XOR_MULT_DOSStub_c393 {
  strings:
    $key_c393 = { 97 fb [2] e3 e3 [2] a4 e1 [2] e3 f0 [2] ad fc [2] a1 f6 [2] b6 fd [2] ad b3 [2] 90 }

  condition:
    any of them
}