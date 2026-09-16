rule TTP_XOR_MULT_DOSStub_4494 {
  strings:
    $key_4494 = { 10 fc [2] 64 e4 [2] 23 e6 [2] 64 f7 [2] 2a fb [2] 26 f1 [2] 31 fa [2] 2a b4 [2] 17 }

  condition:
    any of them
}