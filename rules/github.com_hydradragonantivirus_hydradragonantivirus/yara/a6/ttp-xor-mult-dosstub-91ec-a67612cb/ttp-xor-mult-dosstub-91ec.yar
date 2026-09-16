rule TTP_XOR_MULT_DOSStub_91ec {
  strings:
    $key_91ec = { c5 84 [2] b1 9c [2] f6 9e [2] b1 8f [2] ff 83 [2] f3 89 [2] e4 82 [2] ff cc [2] c2 }

  condition:
    any of them
}