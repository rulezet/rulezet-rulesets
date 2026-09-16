rule TTP_XOR_MULT_DOSStub_f5ec {
  strings:
    $key_f5ec = { a1 84 [2] d5 9c [2] 92 9e [2] d5 8f [2] 9b 83 [2] 97 89 [2] 80 82 [2] 9b cc [2] a6 }

  condition:
    any of them
}