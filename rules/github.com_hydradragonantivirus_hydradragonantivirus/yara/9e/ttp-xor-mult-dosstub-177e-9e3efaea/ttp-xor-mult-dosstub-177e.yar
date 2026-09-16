rule TTP_XOR_MULT_DOSStub_177e {
  strings:
    $key_177e = { 43 16 [2] 37 0e [2] 70 0c [2] 37 1d [2] 79 11 [2] 75 1b [2] 62 10 [2] 79 5e [2] 44 }

  condition:
    any of them
}