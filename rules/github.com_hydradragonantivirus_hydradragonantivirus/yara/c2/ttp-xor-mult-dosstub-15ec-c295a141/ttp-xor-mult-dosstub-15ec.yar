rule TTP_XOR_MULT_DOSStub_15ec {
  strings:
    $key_15ec = { 41 84 [2] 35 9c [2] 72 9e [2] 35 8f [2] 7b 83 [2] 77 89 [2] 60 82 [2] 7b cc [2] 46 }

  condition:
    any of them
}