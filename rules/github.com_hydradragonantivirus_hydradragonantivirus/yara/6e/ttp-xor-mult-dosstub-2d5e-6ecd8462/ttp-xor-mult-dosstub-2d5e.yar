rule TTP_XOR_MULT_DOSStub_2d5e {
  strings:
    $key_2d5e = { 79 36 [2] 0d 2e [2] 4a 2c [2] 0d 3d [2] 43 31 [2] 4f 3b [2] 58 30 [2] 43 7e [2] 7e }

  condition:
    any of them
}