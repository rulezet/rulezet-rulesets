rule TTP_XOR_MULT_DOSStub_1e7e {
  strings:
    $key_1e7e = { 4a 16 [2] 3e 0e [2] 79 0c [2] 3e 1d [2] 70 11 [2] 7c 1b [2] 6b 10 [2] 70 5e [2] 4d }

  condition:
    any of them
}