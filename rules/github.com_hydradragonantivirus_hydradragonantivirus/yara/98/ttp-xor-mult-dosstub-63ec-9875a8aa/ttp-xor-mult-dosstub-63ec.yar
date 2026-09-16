rule TTP_XOR_MULT_DOSStub_63ec {
  strings:
    $key_63ec = { 37 84 [2] 43 9c [2] 04 9e [2] 43 8f [2] 0d 83 [2] 01 89 [2] 16 82 [2] 0d cc [2] 30 }

  condition:
    any of them
}