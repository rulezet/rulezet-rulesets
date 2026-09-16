rule TTP_XOR_MULT_DOSStub_60ec {
  strings:
    $key_60ec = { 34 84 [2] 40 9c [2] 07 9e [2] 40 8f [2] 0e 83 [2] 02 89 [2] 15 82 [2] 0e cc [2] 33 }

  condition:
    any of them
}