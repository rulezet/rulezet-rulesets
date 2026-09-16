rule TTP_XOR_MULT_DOSStub_83ec {
  strings:
    $key_83ec = { d7 84 [2] a3 9c [2] e4 9e [2] a3 8f [2] ed 83 [2] e1 89 [2] f6 82 [2] ed cc [2] d0 }

  condition:
    any of them
}