rule TTP_XOR_MULT_DOSStub_c792 {
  strings:
    $key_c792 = { 93 fa [2] e7 e2 [2] a0 e0 [2] e7 f1 [2] a9 fd [2] a5 f7 [2] b2 fc [2] a9 b2 [2] 94 }

  condition:
    any of them
}