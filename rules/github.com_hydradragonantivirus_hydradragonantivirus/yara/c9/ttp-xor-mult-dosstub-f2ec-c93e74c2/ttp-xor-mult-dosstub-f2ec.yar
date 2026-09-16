rule TTP_XOR_MULT_DOSStub_f2ec {
  strings:
    $key_f2ec = { a6 84 [2] d2 9c [2] 95 9e [2] d2 8f [2] 9c 83 [2] 90 89 [2] 87 82 [2] 9c cc [2] a1 }

  condition:
    any of them
}