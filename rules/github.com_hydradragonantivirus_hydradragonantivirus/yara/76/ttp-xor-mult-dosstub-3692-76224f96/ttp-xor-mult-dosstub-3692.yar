rule TTP_XOR_MULT_DOSStub_3692 {
  strings:
    $key_3692 = { 62 fa [2] 16 e2 [2] 51 e0 [2] 16 f1 [2] 58 fd [2] 54 f7 [2] 43 fc [2] 58 b2 [2] 65 }

  condition:
    any of them
}