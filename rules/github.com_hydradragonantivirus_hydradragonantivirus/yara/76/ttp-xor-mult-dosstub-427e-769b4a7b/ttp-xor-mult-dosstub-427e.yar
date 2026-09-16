rule TTP_XOR_MULT_DOSStub_427e {
  strings:
    $key_427e = { 16 16 [2] 62 0e [2] 25 0c [2] 62 1d [2] 2c 11 [2] 20 1b [2] 37 10 [2] 2c 5e [2] 11 }

  condition:
    any of them
}