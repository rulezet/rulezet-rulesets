rule TTP_XOR_MULT_DOSStub_967d {
  strings:
    $key_967d = { c2 15 [2] b6 0d [2] f1 0f [2] b6 1e [2] f8 12 [2] f4 18 [2] e3 13 [2] f8 5d [2] c5 }

  condition:
    any of them
}