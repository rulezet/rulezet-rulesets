rule TTP_XOR_MULT_DOSStub_7c5e {
  strings:
    $key_7c5e = { 28 36 [2] 5c 2e [2] 1b 2c [2] 5c 3d [2] 12 31 [2] 1e 3b [2] 09 30 [2] 12 7e [2] 2f }

  condition:
    any of them
}