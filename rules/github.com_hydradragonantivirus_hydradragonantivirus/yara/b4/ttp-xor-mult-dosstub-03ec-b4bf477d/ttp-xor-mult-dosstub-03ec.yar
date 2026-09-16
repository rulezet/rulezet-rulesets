rule TTP_XOR_MULT_DOSStub_03ec {
  strings:
    $key_03ec = { 57 84 [2] 23 9c [2] 64 9e [2] 23 8f [2] 6d 83 [2] 61 89 [2] 76 82 [2] 6d cc [2] 50 }

  condition:
    any of them
}