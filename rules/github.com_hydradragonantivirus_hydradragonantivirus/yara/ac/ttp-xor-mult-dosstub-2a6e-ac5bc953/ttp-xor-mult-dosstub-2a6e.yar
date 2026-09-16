rule TTP_XOR_MULT_DOSStub_2a6e {
  strings:
    $key_2a6e = { 7e 06 [2] 0a 1e [2] 4d 1c [2] 0a 0d [2] 44 01 [2] 48 0b [2] 5f 00 [2] 44 4e [2] 79 }

  condition:
    any of them
}