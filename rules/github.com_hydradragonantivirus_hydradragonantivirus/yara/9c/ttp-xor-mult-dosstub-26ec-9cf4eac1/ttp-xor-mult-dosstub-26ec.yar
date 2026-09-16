rule TTP_XOR_MULT_DOSStub_26ec {
  strings:
    $key_26ec = { 72 84 [2] 06 9c [2] 41 9e [2] 06 8f [2] 48 83 [2] 44 89 [2] 53 82 [2] 48 cc [2] 75 }

  condition:
    any of them
}