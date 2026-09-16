rule TTP_XOR_MULT_DOSStub_265e {
  strings:
    $key_265e = { 72 36 [2] 06 2e [2] 41 2c [2] 06 3d [2] 48 31 [2] 44 3b [2] 53 30 [2] 48 7e [2] 75 }

  condition:
    any of them
}