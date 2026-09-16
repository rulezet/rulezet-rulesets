rule TTP_XOR_MULT_DOSStub_83f2 {
  strings:
    $key_83f2 = { d7 9a [2] a3 82 [2] e4 80 [2] a3 91 [2] ed 9d [2] e1 97 [2] f6 9c [2] ed d2 [2] d0 }

  condition:
    any of them
}