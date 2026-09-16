rule TTP_XOR_MULT_DOSStub_025e {
  strings:
    $key_025e = { 56 36 [2] 22 2e [2] 65 2c [2] 22 3d [2] 6c 31 [2] 60 3b [2] 77 30 [2] 6c 7e [2] 51 }

  condition:
    any of them
}