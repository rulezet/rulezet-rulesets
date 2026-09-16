rule TTP_XOR_MULT_DOSStub_90f6 {
  strings:
    $key_90f6 = { c4 9e [2] b0 86 [2] f7 84 [2] b0 95 [2] fe 99 [2] f2 93 [2] e5 98 [2] fe d6 [2] c3 }

  condition:
    any of them
}