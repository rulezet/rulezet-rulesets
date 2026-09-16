rule TTP_XOR_MULT_DOSStub_225e {
  strings:
    $key_225e = { 76 36 [2] 02 2e [2] 45 2c [2] 02 3d [2] 4c 31 [2] 40 3b [2] 57 30 [2] 4c 7e [2] 71 }

  condition:
    any of them
}