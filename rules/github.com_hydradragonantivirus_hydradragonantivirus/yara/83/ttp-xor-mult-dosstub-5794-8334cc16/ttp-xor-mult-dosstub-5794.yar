rule TTP_XOR_MULT_DOSStub_5794 {
  strings:
    $key_5794 = { 03 fc [2] 77 e4 [2] 30 e6 [2] 77 f7 [2] 39 fb [2] 35 f1 [2] 22 fa [2] 39 b4 [2] 04 }

  condition:
    any of them
}