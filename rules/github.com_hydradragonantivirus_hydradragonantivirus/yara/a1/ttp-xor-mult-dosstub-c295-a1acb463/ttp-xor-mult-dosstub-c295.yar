rule TTP_XOR_MULT_DOSStub_c295 {
  strings:
    $key_c295 = { 96 fd [2] e2 e5 [2] a5 e7 [2] e2 f6 [2] ac fa [2] a0 f0 [2] b7 fb [2] ac b5 [2] 91 }

  condition:
    any of them
}