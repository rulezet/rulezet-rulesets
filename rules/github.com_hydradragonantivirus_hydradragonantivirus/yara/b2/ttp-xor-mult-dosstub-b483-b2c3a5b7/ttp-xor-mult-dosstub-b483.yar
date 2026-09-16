rule TTP_XOR_MULT_DOSStub_b483 {
  strings:
    $key_b483 = { e0 eb [2] 94 f3 [2] d3 f1 [2] 94 e0 [2] da ec [2] d6 e6 [2] c1 ed [2] da a3 [2] e7 }

  condition:
    any of them
}