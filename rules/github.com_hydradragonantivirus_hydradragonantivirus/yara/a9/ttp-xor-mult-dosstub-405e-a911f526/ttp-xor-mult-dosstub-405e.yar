rule TTP_XOR_MULT_DOSStub_405e {
  strings:
    $key_405e = { 14 36 [2] 60 2e [2] 27 2c [2] 60 3d [2] 2e 31 [2] 22 3b [2] 35 30 [2] 2e 7e [2] 13 }

  condition:
    any of them
}