rule TTP_XOR_MULT_DOSStub_e4ec {
  strings:
    $key_e4ec = { b0 84 [2] c4 9c [2] 83 9e [2] c4 8f [2] 8a 83 [2] 86 89 [2] 91 82 [2] 8a cc [2] b7 }

  condition:
    any of them
}