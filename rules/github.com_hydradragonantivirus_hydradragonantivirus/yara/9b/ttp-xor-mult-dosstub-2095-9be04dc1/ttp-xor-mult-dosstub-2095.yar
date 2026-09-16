rule TTP_XOR_MULT_DOSStub_2095 {
  strings:
    $key_2095 = { 74 fd [2] 00 e5 [2] 47 e7 [2] 00 f6 [2] 4e fa [2] 42 f0 [2] 55 fb [2] 4e b5 [2] 73 }

  condition:
    any of them
}