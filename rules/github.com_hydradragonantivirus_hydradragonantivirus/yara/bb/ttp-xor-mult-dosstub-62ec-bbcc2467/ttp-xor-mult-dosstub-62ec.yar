rule TTP_XOR_MULT_DOSStub_62ec {
  strings:
    $key_62ec = { 36 84 [2] 42 9c [2] 05 9e [2] 42 8f [2] 0c 83 [2] 00 89 [2] 17 82 [2] 0c cc [2] 31 }

  condition:
    any of them
}