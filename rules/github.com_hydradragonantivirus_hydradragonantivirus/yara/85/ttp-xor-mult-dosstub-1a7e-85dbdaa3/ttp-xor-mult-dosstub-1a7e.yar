rule TTP_XOR_MULT_DOSStub_1a7e {
  strings:
    $key_1a7e = { 4e 16 [2] 3a 0e [2] 7d 0c [2] 3a 1d [2] 74 11 [2] 78 1b [2] 6f 10 [2] 74 5e [2] 49 }

  condition:
    any of them
}