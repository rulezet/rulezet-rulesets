rule TTP_XOR_MULT_DOSStub_5e7e {
  strings:
    $key_5e7e = { 0a 16 [2] 7e 0e [2] 39 0c [2] 7e 1d [2] 30 11 [2] 3c 1b [2] 2b 10 [2] 30 5e [2] 0d }

  condition:
    any of them
}