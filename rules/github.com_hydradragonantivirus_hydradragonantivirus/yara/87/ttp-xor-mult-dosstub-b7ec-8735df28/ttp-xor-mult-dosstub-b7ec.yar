rule TTP_XOR_MULT_DOSStub_b7ec {
  strings:
    $key_b7ec = { e3 84 [2] 97 9c [2] d0 9e [2] 97 8f [2] d9 83 [2] d5 89 [2] c2 82 [2] d9 cc [2] e4 }

  condition:
    any of them
}