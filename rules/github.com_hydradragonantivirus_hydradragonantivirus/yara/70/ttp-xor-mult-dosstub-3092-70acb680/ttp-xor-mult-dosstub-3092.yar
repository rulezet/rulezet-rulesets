rule TTP_XOR_MULT_DOSStub_3092 {
  strings:
    $key_3092 = { 64 fa [2] 10 e2 [2] 57 e0 [2] 10 f1 [2] 5e fd [2] 52 f7 [2] 45 fc [2] 5e b2 [2] 63 }

  condition:
    any of them
}