rule TTP_XOR_MULT_DOSStub_2c5e {
  strings:
    $key_2c5e = { 78 36 [2] 0c 2e [2] 4b 2c [2] 0c 3d [2] 42 31 [2] 4e 3b [2] 59 30 [2] 42 7e [2] 7f }

  condition:
    any of them
}