rule TTP_XOR_MULT_DOSStub_145e {
  strings:
    $key_145e = { 40 36 [2] 34 2e [2] 73 2c [2] 34 3d [2] 7a 31 [2] 76 3b [2] 61 30 [2] 7a 7e [2] 47 }

  condition:
    any of them
}