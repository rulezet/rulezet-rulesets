rule TTP_XOR_MULT_DOSStub_b0ee {
  strings:
    $key_b0ee = { e4 86 [2] 90 9e [2] d7 9c [2] 90 8d [2] de 81 [2] d2 8b [2] c5 80 [2] de ce [2] e3 }

  condition:
    any of them
}