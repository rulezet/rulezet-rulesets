rule TTP_XOR_MULT_DOSStub_e599 {
  strings:
    $key_e599 = { b1 f1 [2] c5 e9 [2] 82 eb [2] c5 fa [2] 8b f6 [2] 87 fc [2] 90 f7 [2] 8b b9 [2] b6 }

  condition:
    any of them
}