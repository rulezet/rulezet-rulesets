rule TTP_XOR_MULT_DOSStub_a5ec {
  strings:
    $key_a5ec = { f1 84 [2] 85 9c [2] c2 9e [2] 85 8f [2] cb 83 [2] c7 89 [2] d0 82 [2] cb cc [2] f6 }

  condition:
    any of them
}