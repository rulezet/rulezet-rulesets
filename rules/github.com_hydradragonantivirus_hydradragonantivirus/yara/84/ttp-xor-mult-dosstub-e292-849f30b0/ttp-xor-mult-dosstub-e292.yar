rule TTP_XOR_MULT_DOSStub_e292 {
  strings:
    $key_e292 = { b6 fa [2] c2 e2 [2] 85 e0 [2] c2 f1 [2] 8c fd [2] 80 f7 [2] 97 fc [2] 8c b2 [2] b1 }

  condition:
    any of them
}