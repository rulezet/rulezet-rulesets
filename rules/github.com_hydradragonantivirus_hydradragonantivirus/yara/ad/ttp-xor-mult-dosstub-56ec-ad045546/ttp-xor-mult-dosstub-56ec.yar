rule TTP_XOR_MULT_DOSStub_56ec {
  strings:
    $key_56ec = { 02 84 [2] 76 9c [2] 31 9e [2] 76 8f [2] 38 83 [2] 34 89 [2] 23 82 [2] 38 cc [2] 05 }

  condition:
    any of them
}