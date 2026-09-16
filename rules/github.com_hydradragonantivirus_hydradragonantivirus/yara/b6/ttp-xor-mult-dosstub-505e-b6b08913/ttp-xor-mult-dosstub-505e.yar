rule TTP_XOR_MULT_DOSStub_505e {
  strings:
    $key_505e = { 04 36 [2] 70 2e [2] 37 2c [2] 70 3d [2] 3e 31 [2] 32 3b [2] 25 30 [2] 3e 7e [2] 03 }

  condition:
    any of them
}