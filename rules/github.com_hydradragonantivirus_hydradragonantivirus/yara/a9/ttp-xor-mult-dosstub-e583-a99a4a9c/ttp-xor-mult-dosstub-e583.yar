rule TTP_XOR_MULT_DOSStub_e583 {
  strings:
    $key_e583 = { b1 eb [2] c5 f3 [2] 82 f1 [2] c5 e0 [2] 8b ec [2] 87 e6 [2] 90 ed [2] 8b a3 [2] b6 }

  condition:
    any of them
}