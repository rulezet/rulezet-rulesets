rule TTP_XOR_MULT_DOSStub_90f0 {
  strings:
    $key_90f0 = { c4 98 [2] b0 80 [2] f7 82 [2] b0 93 [2] fe 9f [2] f2 95 [2] e5 9e [2] fe d0 [2] c3 }

  condition:
    any of them
}