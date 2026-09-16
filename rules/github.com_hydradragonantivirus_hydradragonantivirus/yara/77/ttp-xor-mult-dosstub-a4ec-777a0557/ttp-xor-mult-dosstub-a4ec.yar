rule TTP_XOR_MULT_DOSStub_a4ec {
  strings:
    $key_a4ec = { f0 84 [2] 84 9c [2] c3 9e [2] 84 8f [2] ca 83 [2] c6 89 [2] d1 82 [2] ca cc [2] f7 }

  condition:
    any of them
}