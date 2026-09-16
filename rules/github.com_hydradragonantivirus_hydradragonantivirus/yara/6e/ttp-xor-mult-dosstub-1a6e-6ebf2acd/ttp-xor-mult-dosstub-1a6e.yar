rule TTP_XOR_MULT_DOSStub_1a6e {
  strings:
    $key_1a6e = { 4e 06 [2] 3a 1e [2] 7d 1c [2] 3a 0d [2] 74 01 [2] 78 0b [2] 6f 00 [2] 74 4e [2] 49 }

  condition:
    any of them
}