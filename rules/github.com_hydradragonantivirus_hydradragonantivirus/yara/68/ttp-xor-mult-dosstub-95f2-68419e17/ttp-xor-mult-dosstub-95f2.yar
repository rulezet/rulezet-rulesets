rule TTP_XOR_MULT_DOSStub_95f2 {
  strings:
    $key_95f2 = { c1 9a [2] b5 82 [2] f2 80 [2] b5 91 [2] fb 9d [2] f7 97 [2] e0 9c [2] fb d2 [2] c6 }

  condition:
    any of them
}