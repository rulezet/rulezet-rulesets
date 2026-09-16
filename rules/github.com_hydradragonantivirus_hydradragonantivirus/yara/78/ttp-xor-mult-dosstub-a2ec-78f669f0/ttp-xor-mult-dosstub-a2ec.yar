rule TTP_XOR_MULT_DOSStub_a2ec {
  strings:
    $key_a2ec = { f6 84 [2] 82 9c [2] c5 9e [2] 82 8f [2] cc 83 [2] c0 89 [2] d7 82 [2] cc cc [2] f1 }

  condition:
    any of them
}