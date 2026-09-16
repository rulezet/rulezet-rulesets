rule TTP_XOR_MULT_DOSStub_c192 {
  strings:
    $key_c192 = { 95 fa [2] e1 e2 [2] a6 e0 [2] e1 f1 [2] af fd [2] a3 f7 [2] b4 fc [2] af b2 [2] 92 }

  condition:
    any of them
}