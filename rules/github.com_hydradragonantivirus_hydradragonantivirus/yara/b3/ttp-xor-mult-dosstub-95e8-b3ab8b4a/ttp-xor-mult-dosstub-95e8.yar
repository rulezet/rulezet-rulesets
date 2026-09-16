rule TTP_XOR_MULT_DOSStub_95e8 {
  strings:
    $key_95e8 = { c1 80 [2] b5 98 [2] f2 9a [2] b5 8b [2] fb 87 [2] f7 8d [2] e0 86 [2] fb c8 [2] c6 }

  condition:
    any of them
}