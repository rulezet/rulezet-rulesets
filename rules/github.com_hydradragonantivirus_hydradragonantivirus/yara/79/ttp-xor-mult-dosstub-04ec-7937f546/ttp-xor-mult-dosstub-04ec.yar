rule TTP_XOR_MULT_DOSStub_04ec {
  strings:
    $key_04ec = { 50 84 [2] 24 9c [2] 63 9e [2] 24 8f [2] 6a 83 [2] 66 89 [2] 71 82 [2] 6a cc [2] 57 }

  condition:
    any of them
}