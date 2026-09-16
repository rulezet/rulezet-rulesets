rule TTP_XOR_MULT_DOSStub_b6ec {
  strings:
    $key_b6ec = { e2 84 [2] 96 9c [2] d1 9e [2] 96 8f [2] d8 83 [2] d4 89 [2] c3 82 [2] d8 cc [2] e5 }

  condition:
    any of them
}