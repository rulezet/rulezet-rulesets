rule TTP_XOR_MULT_DOSStub_155e {
  strings:
    $key_155e = { 41 36 [2] 35 2e [2] 72 2c [2] 35 3d [2] 7b 31 [2] 77 3b [2] 60 30 [2] 7b 7e [2] 46 }

  condition:
    any of them
}