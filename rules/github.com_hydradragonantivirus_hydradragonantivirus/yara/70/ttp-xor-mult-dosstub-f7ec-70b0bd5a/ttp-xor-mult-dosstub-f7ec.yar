rule TTP_XOR_MULT_DOSStub_f7ec {
  strings:
    $key_f7ec = { a3 84 [2] d7 9c [2] 90 9e [2] d7 8f [2] 99 83 [2] 95 89 [2] 82 82 [2] 99 cc [2] a4 }

  condition:
    any of them
}