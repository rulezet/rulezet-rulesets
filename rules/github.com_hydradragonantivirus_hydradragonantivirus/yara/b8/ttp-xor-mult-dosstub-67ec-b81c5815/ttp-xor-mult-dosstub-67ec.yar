rule TTP_XOR_MULT_DOSStub_67ec {
  strings:
    $key_67ec = { 33 84 [2] 47 9c [2] 00 9e [2] 47 8f [2] 09 83 [2] 05 89 [2] 12 82 [2] 09 cc [2] 34 }

  condition:
    any of them
}