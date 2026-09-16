rule TTP_XOR_MULT_DOSStub_7492 {
  strings:
    $key_7492 = { 20 fa [2] 54 e2 [2] 13 e0 [2] 54 f1 [2] 1a fd [2] 16 f7 [2] 01 fc [2] 1a b2 [2] 27 }

  condition:
    any of them
}