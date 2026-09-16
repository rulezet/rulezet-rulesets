rule TTP_XOR_MULT_DOSStub_20ec {
  strings:
    $key_20ec = { 74 84 [2] 00 9c [2] 47 9e [2] 00 8f [2] 4e 83 [2] 42 89 [2] 55 82 [2] 4e cc [2] 73 }

  condition:
    any of them
}