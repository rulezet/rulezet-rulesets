rule TTP_XOR_MULT_DOSStub_1b5e {
  strings:
    $key_1b5e = { 4f 36 [2] 3b 2e [2] 7c 2c [2] 3b 3d [2] 75 31 [2] 79 3b [2] 6e 30 [2] 75 7e [2] 48 }

  condition:
    any of them
}