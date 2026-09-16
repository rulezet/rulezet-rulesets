rule TTP_XOR_MULT_DOSStub_e088 {
  strings:
    $key_e088 = { b4 e0 [2] c0 f8 [2] 87 fa [2] c0 eb [2] 8e e7 [2] 82 ed [2] 95 e6 [2] 8e a8 [2] b3 }

  condition:
    any of them
}