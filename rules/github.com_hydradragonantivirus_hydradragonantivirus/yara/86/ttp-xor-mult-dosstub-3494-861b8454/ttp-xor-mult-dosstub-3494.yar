rule TTP_XOR_MULT_DOSStub_3494 {
  strings:
    $key_3494 = { 60 fc [2] 14 e4 [2] 53 e6 [2] 14 f7 [2] 5a fb [2] 56 f1 [2] 41 fa [2] 5a b4 [2] 67 }

  condition:
    any of them
}