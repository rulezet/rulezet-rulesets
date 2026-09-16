rule TTP_XOR_MULT_DOSStub_407e {
  strings:
    $key_407e = { 14 16 [2] 60 0e [2] 27 0c [2] 60 1d [2] 2e 11 [2] 22 1b [2] 35 10 [2] 2e 5e [2] 13 }

  condition:
    any of them
}