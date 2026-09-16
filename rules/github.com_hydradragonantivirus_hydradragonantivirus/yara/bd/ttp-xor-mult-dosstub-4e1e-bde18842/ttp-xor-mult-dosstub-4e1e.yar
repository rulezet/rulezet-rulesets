rule TTP_XOR_MULT_DOSStub_4e1e {
  strings:
    $key_4e1e = { 1a 76 [2] 6e 6e [2] 29 6c [2] 6e 7d [2] 20 71 [2] 2c 7b [2] 3b 70 [2] 20 3e [2] 1d }

  condition:
    any of them
}