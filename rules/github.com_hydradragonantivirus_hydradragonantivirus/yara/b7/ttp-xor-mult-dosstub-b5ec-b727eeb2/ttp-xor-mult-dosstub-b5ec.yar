rule TTP_XOR_MULT_DOSStub_b5ec {
  strings:
    $key_b5ec = { e1 84 [2] 95 9c [2] d2 9e [2] 95 8f [2] db 83 [2] d7 89 [2] c0 82 [2] db cc [2] e6 }

  condition:
    any of them
}