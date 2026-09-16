rule TTP_XOR_MULT_DOSStub_447e {
  strings:
    $key_447e = { 10 16 [2] 64 0e [2] 23 0c [2] 64 1d [2] 2a 11 [2] 26 1b [2] 31 10 [2] 2a 5e [2] 17 }

  condition:
    any of them
}