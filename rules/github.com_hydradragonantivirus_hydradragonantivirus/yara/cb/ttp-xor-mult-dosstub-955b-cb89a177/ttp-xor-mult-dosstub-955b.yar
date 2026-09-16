rule TTP_XOR_MULT_DOSStub_955b {
  strings:
    $key_955b = { c1 33 [2] b5 2b [2] f2 29 [2] b5 38 [2] fb 34 [2] f7 3e [2] e0 35 [2] fb 7b [2] c6 }

  condition:
    any of them
}