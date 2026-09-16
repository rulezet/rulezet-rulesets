rule TTP_XOR_MULT_DOSStub_e799 {
  strings:
    $key_e799 = { b3 f1 [2] c7 e9 [2] 80 eb [2] c7 fa [2] 89 f6 [2] 85 fc [2] 92 f7 [2] 89 b9 [2] b4 }

  condition:
    any of them
}