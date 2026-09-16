rule TTP_XOR_MULT_DOSStub_3a5e {
  strings:
    $key_3a5e = { 6e 36 [2] 1a 2e [2] 5d 2c [2] 1a 3d [2] 54 31 [2] 58 3b [2] 4f 30 [2] 54 7e [2] 69 }

  condition:
    any of them
}