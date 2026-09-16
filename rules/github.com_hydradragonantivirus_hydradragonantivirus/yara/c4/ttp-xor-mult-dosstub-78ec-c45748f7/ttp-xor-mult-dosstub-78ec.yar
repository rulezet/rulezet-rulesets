rule TTP_XOR_MULT_DOSStub_78ec {
  strings:
    $key_78ec = { 2c 84 [2] 58 9c [2] 1f 9e [2] 58 8f [2] 16 83 [2] 1a 89 [2] 0d 82 [2] 16 cc [2] 2b }

  condition:
    any of them
}