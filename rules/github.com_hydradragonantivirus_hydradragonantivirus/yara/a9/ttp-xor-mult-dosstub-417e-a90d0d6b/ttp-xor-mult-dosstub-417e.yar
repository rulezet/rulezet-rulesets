rule TTP_XOR_MULT_DOSStub_417e {
  strings:
    $key_417e = { 15 16 [2] 61 0e [2] 26 0c [2] 61 1d [2] 2f 11 [2] 23 1b [2] 34 10 [2] 2f 5e [2] 12 }

  condition:
    any of them
}