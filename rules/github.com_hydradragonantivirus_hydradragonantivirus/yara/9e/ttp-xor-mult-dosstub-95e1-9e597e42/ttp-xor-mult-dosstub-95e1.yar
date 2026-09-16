rule TTP_XOR_MULT_DOSStub_95e1 {
  strings:
    $key_95e1 = { c1 89 [2] b5 91 [2] f2 93 [2] b5 82 [2] fb 8e [2] f7 84 [2] e0 8f [2] fb c1 [2] c6 }

  condition:
    any of them
}