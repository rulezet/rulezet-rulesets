rule TTP_XOR_MULT_DOSStub_e499 {
  strings:
    $key_e499 = { b0 f1 [2] c4 e9 [2] 83 eb [2] c4 fa [2] 8a f6 [2] 86 fc [2] 91 f7 [2] 8a b9 [2] b7 }

  condition:
    any of them
}