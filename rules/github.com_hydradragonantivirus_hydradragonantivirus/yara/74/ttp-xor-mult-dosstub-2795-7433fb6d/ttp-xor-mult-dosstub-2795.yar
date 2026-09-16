rule TTP_XOR_MULT_DOSStub_2795 {
  strings:
    $key_2795 = { 73 fd [2] 07 e5 [2] 40 e7 [2] 07 f6 [2] 49 fa [2] 45 f0 [2] 52 fb [2] 49 b5 [2] 74 }

  condition:
    any of them
}