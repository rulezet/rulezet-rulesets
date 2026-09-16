rule TTP_XOR_MULT_DOSStub_17ec {
  strings:
    $key_17ec = { 43 84 [2] 37 9c [2] 70 9e [2] 37 8f [2] 79 83 [2] 75 89 [2] 62 82 [2] 79 cc [2] 44 }

  condition:
    any of them
}