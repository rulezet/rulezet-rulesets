rule TTP_XOR_MULT_DOSStub_7f5e {
  strings:
    $key_7f5e = { 2b 36 [2] 5f 2e [2] 18 2c [2] 5f 3d [2] 11 31 [2] 1d 3b [2] 0a 30 [2] 11 7e [2] 2c }

  condition:
    any of them
}