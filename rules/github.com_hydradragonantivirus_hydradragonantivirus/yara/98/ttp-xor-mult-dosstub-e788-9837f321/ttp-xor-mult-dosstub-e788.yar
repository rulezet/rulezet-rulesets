rule TTP_XOR_MULT_DOSStub_e788 {
  strings:
    $key_e788 = { b3 e0 [2] c7 f8 [2] 80 fa [2] c7 eb [2] 89 e7 [2] 85 ed [2] 92 e6 [2] 89 a8 [2] b4 }

  condition:
    any of them
}