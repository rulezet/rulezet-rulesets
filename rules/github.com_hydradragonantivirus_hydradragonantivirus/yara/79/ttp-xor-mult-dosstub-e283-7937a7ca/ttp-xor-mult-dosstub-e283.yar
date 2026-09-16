rule TTP_XOR_MULT_DOSStub_e283 {
  strings:
    $key_e283 = { b6 eb [2] c2 f3 [2] 85 f1 [2] c2 e0 [2] 8c ec [2] 80 e6 [2] 97 ed [2] 8c a3 [2] b1 }

  condition:
    any of them
}