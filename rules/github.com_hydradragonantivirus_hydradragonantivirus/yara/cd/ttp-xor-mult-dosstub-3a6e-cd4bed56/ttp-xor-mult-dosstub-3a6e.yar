rule TTP_XOR_MULT_DOSStub_3a6e {
  strings:
    $key_3a6e = { 6e 06 [2] 1a 1e [2] 5d 1c [2] 1a 0d [2] 54 01 [2] 58 0b [2] 4f 00 [2] 54 4e [2] 69 }

  condition:
    any of them
}