rule TTP_XOR_MULT_DOSStub_96ec {
  strings:
    $key_96ec = { c2 84 [2] b6 9c [2] f1 9e [2] b6 8f [2] f8 83 [2] f4 89 [2] e3 82 [2] f8 cc [2] c5 }

  condition:
    any of them
}