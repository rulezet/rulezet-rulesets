rule TTP_XOR_MULT_DOSStub_e285 {
  strings:
    $key_e285 = { b6 ed [2] c2 f5 [2] 85 f7 [2] c2 e6 [2] 8c ea [2] 80 e0 [2] 97 eb [2] 8c a5 [2] b1 }

  condition:
    any of them
}