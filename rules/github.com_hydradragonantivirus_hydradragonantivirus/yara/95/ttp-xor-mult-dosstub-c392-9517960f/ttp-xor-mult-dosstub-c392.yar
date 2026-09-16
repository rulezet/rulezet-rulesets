rule TTP_XOR_MULT_DOSStub_c392 {
  strings:
    $key_c392 = { 97 fa [2] e3 e2 [2] a4 e0 [2] e3 f1 [2] ad fd [2] a1 f7 [2] b6 fc [2] ad b2 [2] 90 }

  condition:
    any of them
}