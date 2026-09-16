rule TTP_XOR_MULT_DOSStub_42ec {
  strings:
    $key_42ec = { 16 84 [2] 62 9c [2] 25 9e [2] 62 8f [2] 2c 83 [2] 20 89 [2] 37 82 [2] 2c cc [2] 11 }

  condition:
    any of them
}