rule TTP_XOR_MULT_DOSStub_21ec {
  strings:
    $key_21ec = { 75 84 [2] 01 9c [2] 46 9e [2] 01 8f [2] 4f 83 [2] 43 89 [2] 54 82 [2] 4f cc [2] 72 }

  condition:
    any of them
}