rule TTP_XOR_MULT_DOSStub_2e4e {
  strings:
    $key_2e4e = { 7a 26 [2] 0e 3e [2] 49 3c [2] 0e 2d [2] 40 21 [2] 4c 2b [2] 5b 20 [2] 40 6e [2] 7d }

  condition:
    any of them
}