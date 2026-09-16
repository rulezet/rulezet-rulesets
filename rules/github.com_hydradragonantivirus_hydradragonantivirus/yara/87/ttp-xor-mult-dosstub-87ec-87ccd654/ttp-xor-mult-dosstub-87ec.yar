rule TTP_XOR_MULT_DOSStub_87ec {
  strings:
    $key_87ec = { d3 84 [2] a7 9c [2] e0 9e [2] a7 8f [2] e9 83 [2] e5 89 [2] f2 82 [2] e9 cc [2] d4 }

  condition:
    any of them
}