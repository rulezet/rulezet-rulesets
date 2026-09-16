rule TTP_XOR_MULT_DOSStub_c199 {
  strings:
    $key_c199 = { 95 f1 [2] e1 e9 [2] a6 eb [2] e1 fa [2] af f6 [2] a3 fc [2] b4 f7 [2] af b9 [2] 92 }

  condition:
    any of them
}