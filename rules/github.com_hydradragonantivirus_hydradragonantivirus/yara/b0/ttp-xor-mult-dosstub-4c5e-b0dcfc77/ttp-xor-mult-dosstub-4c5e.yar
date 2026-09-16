rule TTP_XOR_MULT_DOSStub_4c5e {
  strings:
    $key_4c5e = { 18 36 [2] 6c 2e [2] 2b 2c [2] 6c 3d [2] 22 31 [2] 2e 3b [2] 39 30 [2] 22 7e [2] 1f }

  condition:
    any of them
}