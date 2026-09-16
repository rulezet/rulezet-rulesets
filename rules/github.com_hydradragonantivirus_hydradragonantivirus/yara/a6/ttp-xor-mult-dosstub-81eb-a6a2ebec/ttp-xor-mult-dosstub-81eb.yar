rule TTP_XOR_MULT_DOSStub_81eb {
  strings:
    $key_81eb = { d5 83 [2] a1 9b [2] e6 99 [2] a1 88 [2] ef 84 [2] e3 8e [2] f4 85 [2] ef cb [2] d2 }

  condition:
    any of them
}