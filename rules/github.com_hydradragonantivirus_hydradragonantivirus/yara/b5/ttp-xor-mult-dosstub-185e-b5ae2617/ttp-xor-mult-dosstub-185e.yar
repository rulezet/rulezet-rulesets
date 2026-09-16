rule TTP_XOR_MULT_DOSStub_185e {
  strings:
    $key_185e = { 4c 36 [2] 38 2e [2] 7f 2c [2] 38 3d [2] 76 31 [2] 7a 3b [2] 6d 30 [2] 76 7e [2] 4b }

  condition:
    any of them
}