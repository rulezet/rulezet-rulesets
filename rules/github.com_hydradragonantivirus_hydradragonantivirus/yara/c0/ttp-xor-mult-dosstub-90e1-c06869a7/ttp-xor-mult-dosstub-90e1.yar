rule TTP_XOR_MULT_DOSStub_90e1 {
  strings:
    $key_90e1 = { c4 89 [2] b0 91 [2] f7 93 [2] b0 82 [2] fe 8e [2] f2 84 [2] e5 8f [2] fe c1 [2] c3 }

  condition:
    any of them
}