rule TTP_XOR_MULT_DOSStub_b788 {
  strings:
    $key_b788 = { e3 e0 [2] 97 f8 [2] d0 fa [2] 97 eb [2] d9 e7 [2] d5 ed [2] c2 e6 [2] d9 a8 [2] e4 }

  condition:
    any of them
}