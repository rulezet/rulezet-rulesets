rule TTP_XOR_MULT_DOSStub_715e {
  strings:
    $key_715e = { 25 36 [2] 51 2e [2] 16 2c [2] 51 3d [2] 1f 31 [2] 13 3b [2] 04 30 [2] 1f 7e [2] 22 }

  condition:
    any of them
}