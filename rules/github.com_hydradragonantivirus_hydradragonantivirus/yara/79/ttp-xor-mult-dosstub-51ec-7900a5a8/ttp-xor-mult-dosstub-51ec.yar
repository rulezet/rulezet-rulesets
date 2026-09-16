rule TTP_XOR_MULT_DOSStub_51ec {
  strings:
    $key_51ec = { 05 84 [2] 71 9c [2] 36 9e [2] 71 8f [2] 3f 83 [2] 33 89 [2] 24 82 [2] 3f cc [2] 02 }

  condition:
    any of them
}