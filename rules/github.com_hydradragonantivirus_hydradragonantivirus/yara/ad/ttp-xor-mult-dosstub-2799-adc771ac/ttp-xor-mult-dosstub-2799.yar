rule TTP_XOR_MULT_DOSStub_2799 {
  strings:
    $key_2799 = { 73 f1 [2] 07 e9 [2] 40 eb [2] 07 fa [2] 49 f6 [2] 45 fc [2] 52 f7 [2] 49 b9 [2] 74 }

  condition:
    any of them
}