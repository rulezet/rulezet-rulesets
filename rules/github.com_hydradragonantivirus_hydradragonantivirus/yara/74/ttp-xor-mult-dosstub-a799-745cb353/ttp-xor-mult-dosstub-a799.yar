rule TTP_XOR_MULT_DOSStub_a799 {
  strings:
    $key_a799 = { f3 f1 [2] 87 e9 [2] c0 eb [2] 87 fa [2] c9 f6 [2] c5 fc [2] d2 f7 [2] c9 b9 [2] f4 }

  condition:
    any of them
}