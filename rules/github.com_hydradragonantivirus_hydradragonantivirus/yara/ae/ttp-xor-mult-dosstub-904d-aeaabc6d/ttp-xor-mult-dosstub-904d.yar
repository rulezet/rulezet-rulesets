rule TTP_XOR_MULT_DOSStub_904d {
  strings:
    $key_904d = { c4 25 [2] b0 3d [2] f7 3f [2] b0 2e [2] fe 22 [2] f2 28 [2] e5 23 [2] fe 6d [2] c3 }

  condition:
    any of them
}