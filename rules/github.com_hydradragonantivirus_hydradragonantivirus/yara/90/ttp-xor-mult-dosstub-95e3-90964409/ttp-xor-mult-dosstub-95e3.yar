rule TTP_XOR_MULT_DOSStub_95e3 {
  strings:
    $key_95e3 = { c1 8b [2] b5 93 [2] f2 91 [2] b5 80 [2] fb 8c [2] f7 86 [2] e0 8d [2] fb c3 [2] c6 }

  condition:
    any of them
}