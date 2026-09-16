rule TTP_XOR_MULT_DOSStub_95e5 {
  strings:
    $key_95e5 = { c1 8d [2] b5 95 [2] f2 97 [2] b5 86 [2] fb 8a [2] f7 80 [2] e0 8b [2] fb c5 [2] c6 }

  condition:
    any of them
}