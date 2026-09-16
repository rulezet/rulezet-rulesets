rule TTP_XOR_MULT_DOSStub_7c7e {
  strings:
    $key_7c7e = { 28 16 [2] 5c 0e [2] 1b 0c [2] 5c 1d [2] 12 11 [2] 1e 1b [2] 09 10 [2] 12 5e [2] 2f }

  condition:
    any of them
}