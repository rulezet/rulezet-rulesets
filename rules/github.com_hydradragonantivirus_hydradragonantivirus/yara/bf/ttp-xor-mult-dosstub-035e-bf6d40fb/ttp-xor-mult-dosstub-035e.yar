rule TTP_XOR_MULT_DOSStub_035e {
  strings:
    $key_035e = { 57 36 [2] 23 2e [2] 64 2c [2] 23 3d [2] 6d 31 [2] 61 3b [2] 76 30 [2] 6d 7e [2] 50 }

  condition:
    any of them
}