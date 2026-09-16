rule TTP_XOR_MULT_DOSStub_95e0 {
  strings:
    $key_95e0 = { c1 88 [2] b5 90 [2] f2 92 [2] b5 83 [2] fb 8f [2] f7 85 [2] e0 8e [2] fb c0 [2] c6 }

  condition:
    any of them
}