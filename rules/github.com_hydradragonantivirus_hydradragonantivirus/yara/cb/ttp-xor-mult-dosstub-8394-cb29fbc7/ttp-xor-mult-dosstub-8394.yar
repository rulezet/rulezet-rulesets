rule TTP_XOR_MULT_DOSStub_8394 {
  strings:
    $key_8394 = { d7 fc [2] a3 e4 [2] e4 e6 [2] a3 f7 [2] ed fb [2] e1 f1 [2] f6 fa [2] ed b4 [2] d0 }

  condition:
    any of them
}