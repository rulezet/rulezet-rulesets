rule TTP_XOR_MULT_DOSStub_6795 {
  strings:
    $key_6795 = { 33 fd [2] 47 e5 [2] 00 e7 [2] 47 f6 [2] 09 fa [2] 05 f0 [2] 12 fb [2] 09 b5 [2] 34 }

  condition:
    any of them
}