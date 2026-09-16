rule TTP_XOR_MULT_DOSStub_3aeb {
  strings:
    $key_3aeb = { 6e 83 [2] 1a 9b [2] 5d 99 [2] 1a 88 [2] 54 84 [2] 58 8e [2] 4f 85 [2] 54 cb [2] 69 }

  condition:
    any of them
}