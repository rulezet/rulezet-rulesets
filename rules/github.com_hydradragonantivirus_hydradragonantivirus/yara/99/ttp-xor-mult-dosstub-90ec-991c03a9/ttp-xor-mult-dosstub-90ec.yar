rule TTP_XOR_MULT_DOSStub_90ec {
  strings:
    $key_90ec = { c4 84 [2] b0 9c [2] f7 9e [2] b0 8f [2] fe 83 [2] f2 89 [2] e5 82 [2] fe cc [2] c3 }

  condition:
    any of them
}