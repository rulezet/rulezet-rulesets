rule TTP_XOR_MULT_DOSStub_86ec {
  strings:
    $key_86ec = { d2 84 [2] a6 9c [2] e1 9e [2] a6 8f [2] e8 83 [2] e4 89 [2] f3 82 [2] e8 cc [2] d5 }

  condition:
    any of them
}