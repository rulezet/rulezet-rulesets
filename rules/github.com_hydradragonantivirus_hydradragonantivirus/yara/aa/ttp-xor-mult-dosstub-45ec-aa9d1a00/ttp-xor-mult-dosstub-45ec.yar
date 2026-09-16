rule TTP_XOR_MULT_DOSStub_45ec {
  strings:
    $key_45ec = { 11 84 [2] 65 9c [2] 22 9e [2] 65 8f [2] 2b 83 [2] 27 89 [2] 30 82 [2] 2b cc [2] 16 }

  condition:
    any of them
}