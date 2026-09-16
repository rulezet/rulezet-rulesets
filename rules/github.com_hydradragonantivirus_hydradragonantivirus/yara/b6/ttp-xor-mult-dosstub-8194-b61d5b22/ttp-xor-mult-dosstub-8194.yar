rule TTP_XOR_MULT_DOSStub_8194 {
  strings:
    $key_8194 = { d5 fc [2] a1 e4 [2] e6 e6 [2] a1 f7 [2] ef fb [2] e3 f1 [2] f4 fa [2] ef b4 [2] d2 }

  condition:
    any of them
}