rule TTP_XOR_MULT_DOSStub_64ec {
  strings:
    $key_64ec = { 30 84 [2] 44 9c [2] 03 9e [2] 44 8f [2] 0a 83 [2] 06 89 [2] 11 82 [2] 0a cc [2] 37 }

  condition:
    any of them
}