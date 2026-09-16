rule TTP_XOR_MULT_DOSStub_32ec {
  strings:
    $key_32ec = { 66 84 [2] 12 9c [2] 55 9e [2] 12 8f [2] 5c 83 [2] 50 89 [2] 47 82 [2] 5c cc [2] 61 }

  condition:
    any of them
}