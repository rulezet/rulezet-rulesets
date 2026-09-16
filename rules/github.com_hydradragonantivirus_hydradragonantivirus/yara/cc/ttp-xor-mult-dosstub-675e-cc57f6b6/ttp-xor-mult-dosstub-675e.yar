rule TTP_XOR_MULT_DOSStub_675e {
  strings:
    $key_675e = { 33 36 [2] 47 2e [2] 00 2c [2] 47 3d [2] 09 31 [2] 05 3b [2] 12 30 [2] 09 7e [2] 34 }

  condition:
    any of them
}