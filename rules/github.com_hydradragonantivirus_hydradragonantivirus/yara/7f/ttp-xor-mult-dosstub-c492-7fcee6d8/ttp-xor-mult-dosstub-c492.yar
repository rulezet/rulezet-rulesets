rule TTP_XOR_MULT_DOSStub_c492 {
  strings:
    $key_c492 = { 90 fa [2] e4 e2 [2] a3 e0 [2] e4 f1 [2] aa fd [2] a6 f7 [2] b1 fc [2] aa b2 [2] 97 }

  condition:
    any of them
}