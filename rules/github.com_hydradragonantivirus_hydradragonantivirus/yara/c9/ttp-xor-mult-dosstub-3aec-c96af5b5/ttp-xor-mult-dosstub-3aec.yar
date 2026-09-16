rule TTP_XOR_MULT_DOSStub_3aec {
  strings:
    $key_3aec = { 6e 84 [2] 1a 9c [2] 5d 9e [2] 1a 8f [2] 54 83 [2] 58 89 [2] 4f 82 [2] 54 cc [2] 69 }

  condition:
    any of them
}