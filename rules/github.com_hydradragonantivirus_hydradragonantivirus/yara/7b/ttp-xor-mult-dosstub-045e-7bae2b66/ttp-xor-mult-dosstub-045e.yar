rule TTP_XOR_MULT_DOSStub_045e {
  strings:
    $key_045e = { 50 36 [2] 24 2e [2] 63 2c [2] 24 3d [2] 6a 31 [2] 66 3b [2] 71 30 [2] 6a 7e [2] 57 }

  condition:
    any of them
}