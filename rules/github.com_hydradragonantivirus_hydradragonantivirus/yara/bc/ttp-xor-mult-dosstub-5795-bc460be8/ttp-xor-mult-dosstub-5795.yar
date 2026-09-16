rule TTP_XOR_MULT_DOSStub_5795 {
  strings:
    $key_5795 = { 03 fd [2] 77 e5 [2] 30 e7 [2] 77 f6 [2] 39 fa [2] 35 f0 [2] 22 fb [2] 39 b5 [2] 04 }

  condition:
    any of them
}