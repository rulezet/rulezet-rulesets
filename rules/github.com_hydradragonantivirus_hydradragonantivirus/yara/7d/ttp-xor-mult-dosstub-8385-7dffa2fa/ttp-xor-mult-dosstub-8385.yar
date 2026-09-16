rule TTP_XOR_MULT_DOSStub_8385 {
  strings:
    $key_8385 = { d7 ed [2] a3 f5 [2] e4 f7 [2] a3 e6 [2] ed ea [2] e1 e0 [2] f6 eb [2] ed a5 [2] d0 }

  condition:
    any of them
}