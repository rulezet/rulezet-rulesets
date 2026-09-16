rule TTP_XOR_MULT_DOSStub_b388 {
  strings:
    $key_b388 = { e7 e0 [2] 93 f8 [2] d4 fa [2] 93 eb [2] dd e7 [2] d1 ed [2] c6 e6 [2] dd a8 [2] e0 }

  condition:
    any of them
}