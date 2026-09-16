rule TTP_XOR_MULT_DOSStub_b694 {
  strings:
    $key_b694 = { e2 fc [2] 96 e4 [2] d1 e6 [2] 96 f7 [2] d8 fb [2] d4 f1 [2] c3 fa [2] d8 b4 [2] e5 }

  condition:
    any of them
}