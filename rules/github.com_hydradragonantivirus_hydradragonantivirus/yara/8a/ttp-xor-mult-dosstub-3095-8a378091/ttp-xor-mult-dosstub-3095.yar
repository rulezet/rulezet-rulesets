rule TTP_XOR_MULT_DOSStub_3095 {
  strings:
    $key_3095 = { 64 fd [2] 10 e5 [2] 57 e7 [2] 10 f6 [2] 5e fa [2] 52 f0 [2] 45 fb [2] 5e b5 [2] 63 }

  condition:
    any of them
}