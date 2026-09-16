rule TTP_XOR_MULT_DOSStub_477e {
  strings:
    $key_477e = { 13 16 [2] 67 0e [2] 20 0c [2] 67 1d [2] 29 11 [2] 25 1b [2] 32 10 [2] 29 5e [2] 14 }

  condition:
    any of them
}