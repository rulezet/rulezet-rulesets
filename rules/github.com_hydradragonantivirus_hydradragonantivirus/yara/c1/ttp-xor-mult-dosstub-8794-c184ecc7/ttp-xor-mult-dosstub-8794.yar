rule TTP_XOR_MULT_DOSStub_8794 {
  strings:
    $key_8794 = { d3 fc [2] a7 e4 [2] e0 e6 [2] a7 f7 [2] e9 fb [2] e5 f1 [2] f2 fa [2] e9 b4 [2] d4 }

  condition:
    any of them
}