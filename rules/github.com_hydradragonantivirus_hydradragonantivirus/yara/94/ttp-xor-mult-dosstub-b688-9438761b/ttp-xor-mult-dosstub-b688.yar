rule TTP_XOR_MULT_DOSStub_b688 {
  strings:
    $key_b688 = { e2 e0 [2] 96 f8 [2] d1 fa [2] 96 eb [2] d8 e7 [2] d4 ed [2] c3 e6 [2] d8 a8 [2] e5 }

  condition:
    any of them
}