rule TTP_XOR_MULT_DOSStub_4d7e {
  strings:
    $key_4d7e = { 19 16 [2] 6d 0e [2] 2a 0c [2] 6d 1d [2] 23 11 [2] 2f 1b [2] 38 10 [2] 23 5e [2] 1e }

  condition:
    any of them
}