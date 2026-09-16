rule TTP_XOR_MULT_DOSStub_b488 {
  strings:
    $key_b488 = { e0 e0 [2] 94 f8 [2] d3 fa [2] 94 eb [2] da e7 [2] d6 ed [2] c1 e6 [2] da a8 [2] e7 }

  condition:
    any of them
}