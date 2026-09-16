rule TTP_XOR_MULT_DOSStub_e3ec {
  strings:
    $key_e3ec = { b7 84 [2] c3 9c [2] 84 9e [2] c3 8f [2] 8d 83 [2] 81 89 [2] 96 82 [2] 8d cc [2] b0 }

  condition:
    any of them
}