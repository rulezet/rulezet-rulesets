rule TTP_XOR_MULT_DOSStub_970d {
  strings:
    $key_970d = { c3 65 [2] b7 7d [2] f0 7f [2] b7 6e [2] f9 62 [2] f5 68 [2] e2 63 [2] f9 2d [2] c4 }

  condition:
    any of them
}