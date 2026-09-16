rule TTP_XOR_MULT_DOSStub_3afc {
  strings:
    $key_3afc = { 6e 94 [2] 1a 8c [2] 5d 8e [2] 1a 9f [2] 54 93 [2] 58 99 [2] 4f 92 [2] 54 dc [2] 69 }

  condition:
    any of them
}