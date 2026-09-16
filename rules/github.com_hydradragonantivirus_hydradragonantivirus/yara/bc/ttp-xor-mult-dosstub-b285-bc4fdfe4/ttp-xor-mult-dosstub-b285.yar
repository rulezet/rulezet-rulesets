rule TTP_XOR_MULT_DOSStub_b285 {
  strings:
    $key_b285 = { e6 ed [2] 92 f5 [2] d5 f7 [2] 92 e6 [2] dc ea [2] d0 e0 [2] c7 eb [2] dc a5 [2] e1 }

  condition:
    any of them
}