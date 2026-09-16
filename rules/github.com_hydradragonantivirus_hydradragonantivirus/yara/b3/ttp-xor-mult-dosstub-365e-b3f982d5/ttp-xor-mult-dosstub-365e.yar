rule TTP_XOR_MULT_DOSStub_365e {
  strings:
    $key_365e = { 62 36 [2] 16 2e [2] 51 2c [2] 16 3d [2] 58 31 [2] 54 3b [2] 43 30 [2] 58 7e [2] 65 }

  condition:
    any of them
}