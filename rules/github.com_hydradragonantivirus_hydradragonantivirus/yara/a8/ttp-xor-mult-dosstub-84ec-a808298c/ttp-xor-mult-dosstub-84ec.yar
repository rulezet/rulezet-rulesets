rule TTP_XOR_MULT_DOSStub_84ec {
  strings:
    $key_84ec = { d0 84 [2] a4 9c [2] e3 9e [2] a4 8f [2] ea 83 [2] e6 89 [2] f1 82 [2] ea cc [2] d7 }

  condition:
    any of them
}