rule TTP_XOR_MULT_DOSStub_005e {
  strings:
    $key_005e = { 54 36 [2] 20 2e [2] 67 2c [2] 20 3d [2] 6e 31 [2] 62 3b [2] 75 30 [2] 6e 7e [2] 53 }

  condition:
    any of them
}