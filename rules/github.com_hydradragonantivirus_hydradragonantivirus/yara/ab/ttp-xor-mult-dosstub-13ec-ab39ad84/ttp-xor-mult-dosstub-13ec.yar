rule TTP_XOR_MULT_DOSStub_13ec {
  strings:
    $key_13ec = { 47 84 [2] 33 9c [2] 74 9e [2] 33 8f [2] 7d 83 [2] 71 89 [2] 66 82 [2] 7d cc [2] 40 }

  condition:
    any of them
}