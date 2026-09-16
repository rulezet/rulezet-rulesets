rule TTP_XOR_MULT_DOSStub_125e {
  strings:
    $key_125e = { 46 36 [2] 32 2e [2] 75 2c [2] 32 3d [2] 7c 31 [2] 70 3b [2] 67 30 [2] 7c 7e [2] 41 }

  condition:
    any of them
}