rule TTP_XOR_MULT_DOSStub_31ec {
  strings:
    $key_31ec = { 65 84 [2] 11 9c [2] 56 9e [2] 11 8f [2] 5f 83 [2] 53 89 [2] 44 82 [2] 5f cc [2] 62 }

  condition:
    any of them
}