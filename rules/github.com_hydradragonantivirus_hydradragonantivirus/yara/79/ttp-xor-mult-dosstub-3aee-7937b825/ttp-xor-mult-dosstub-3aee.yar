rule TTP_XOR_MULT_DOSStub_3aee {
  strings:
    $key_3aee = { 6e 86 [2] 1a 9e [2] 5d 9c [2] 1a 8d [2] 54 81 [2] 58 8b [2] 4f 80 [2] 54 ce [2] 69 }

  condition:
    any of them
}