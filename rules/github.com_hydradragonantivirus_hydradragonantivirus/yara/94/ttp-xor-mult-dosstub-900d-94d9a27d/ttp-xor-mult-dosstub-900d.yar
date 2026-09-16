rule TTP_XOR_MULT_DOSStub_900d {
  strings:
    $key_900d = { c4 65 [2] b0 7d [2] f7 7f [2] b0 6e [2] fe 62 [2] f2 68 [2] e5 63 [2] fe 2d [2] c3 }

  condition:
    any of them
}