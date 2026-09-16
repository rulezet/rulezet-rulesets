rule TTP_XOR_MULT_DOSStub_8785 {
  strings:
    $key_8785 = { d3 ed [2] a7 f5 [2] e0 f7 [2] a7 e6 [2] e9 ea [2] e5 e0 [2] f2 eb [2] e9 a5 [2] d4 }

  condition:
    any of them
}