rule TTP_XOR_MULT_DOSStub_83f0 {
  strings:
    $key_83f0 = { d7 98 [2] a3 80 [2] e4 82 [2] a3 93 [2] ed 9f [2] e1 95 [2] f6 9e [2] ed d0 [2] d0 }

  condition:
    any of them
}