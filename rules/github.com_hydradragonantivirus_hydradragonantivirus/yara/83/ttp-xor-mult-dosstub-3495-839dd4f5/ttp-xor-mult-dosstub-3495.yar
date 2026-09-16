rule TTP_XOR_MULT_DOSStub_3495 {
  strings:
    $key_3495 = { 60 fd [2] 14 e5 [2] 53 e7 [2] 14 f6 [2] 5a fa [2] 56 f0 [2] 41 fb [2] 5a b5 [2] 67 }

  condition:
    any of them
}