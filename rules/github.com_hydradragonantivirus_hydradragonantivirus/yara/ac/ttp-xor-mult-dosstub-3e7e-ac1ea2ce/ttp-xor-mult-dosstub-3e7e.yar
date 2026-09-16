rule TTP_XOR_MULT_DOSStub_3e7e {
  strings:
    $key_3e7e = { 6a 16 [2] 1e 0e [2] 59 0c [2] 1e 1d [2] 50 11 [2] 5c 1b [2] 4b 10 [2] 50 5e [2] 6d }

  condition:
    any of them
}