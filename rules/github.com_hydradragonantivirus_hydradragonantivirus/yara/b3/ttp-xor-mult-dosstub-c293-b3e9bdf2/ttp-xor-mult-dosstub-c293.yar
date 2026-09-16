rule TTP_XOR_MULT_DOSStub_c293 {
  strings:
    $key_c293 = { 96 fb [2] e2 e3 [2] a5 e1 [2] e2 f0 [2] ac fc [2] a0 f6 [2] b7 fd [2] ac b3 [2] 91 }

  condition:
    any of them
}