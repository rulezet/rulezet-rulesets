rule TTP_XOR_MULT_DOSStub_81ec {
  strings:
    $key_81ec = { d5 84 [2] a1 9c [2] e6 9e [2] a1 8f [2] ef 83 [2] e3 89 [2] f4 82 [2] ef cc [2] d2 }

  condition:
    any of them
}