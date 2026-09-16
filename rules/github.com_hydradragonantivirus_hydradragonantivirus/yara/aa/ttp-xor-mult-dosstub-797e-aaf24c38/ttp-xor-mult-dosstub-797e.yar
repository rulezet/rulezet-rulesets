rule TTP_XOR_MULT_DOSStub_797e {
  strings:
    $key_797e = { 2d 16 [2] 59 0e [2] 1e 0c [2] 59 1d [2] 17 11 [2] 1b 1b [2] 0c 10 [2] 17 5e [2] 2a }

  condition:
    any of them
}