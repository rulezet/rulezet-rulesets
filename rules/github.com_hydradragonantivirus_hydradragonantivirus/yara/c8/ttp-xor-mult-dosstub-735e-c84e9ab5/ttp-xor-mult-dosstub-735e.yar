rule TTP_XOR_MULT_DOSStub_735e {
  strings:
    $key_735e = { 27 36 [2] 53 2e [2] 14 2c [2] 53 3d [2] 1d 31 [2] 11 3b [2] 06 30 [2] 1d 7e [2] 20 }

  condition:
    any of them
}