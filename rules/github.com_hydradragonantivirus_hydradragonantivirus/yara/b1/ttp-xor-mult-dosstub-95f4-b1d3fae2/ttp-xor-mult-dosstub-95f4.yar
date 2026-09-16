rule TTP_XOR_MULT_DOSStub_95f4 {
  strings:
    $key_95f4 = { c1 9c [2] b5 84 [2] f2 86 [2] b5 97 [2] fb 9b [2] f7 91 [2] e0 9a [2] fb d4 [2] c6 }

  condition:
    any of them
}