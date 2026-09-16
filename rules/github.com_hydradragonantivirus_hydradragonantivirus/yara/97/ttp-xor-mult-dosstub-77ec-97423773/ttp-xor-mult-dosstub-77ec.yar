rule TTP_XOR_MULT_DOSStub_77ec {
  strings:
    $key_77ec = { 23 84 [2] 57 9c [2] 10 9e [2] 57 8f [2] 19 83 [2] 15 89 [2] 02 82 [2] 19 cc [2] 24 }

  condition:
    any of them
}