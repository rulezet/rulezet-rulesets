rule TTP_XOR_MULT_DOSStub_c093 {
  strings:
    $key_c093 = { 94 fb [2] e0 e3 [2] a7 e1 [2] e0 f0 [2] ae fc [2] a2 f6 [2] b5 fd [2] ae b3 [2] 93 }

  condition:
    any of them
}