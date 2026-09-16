rule TTP_XOR_MULT_DOSStub_6095 {
  strings:
    $key_6095 = { 34 fd [2] 40 e5 [2] 07 e7 [2] 40 f6 [2] 0e fa [2] 02 f0 [2] 15 fb [2] 0e b5 [2] 33 }

  condition:
    any of them
}