rule TTP_XOR_MULT_DOSStub_8793 {
  strings:
    $key_8793 = { d3 fb [2] a7 e3 [2] e0 e1 [2] a7 f0 [2] e9 fc [2] e5 f6 [2] f2 fd [2] e9 b3 [2] d4 }

  condition:
    any of them
}