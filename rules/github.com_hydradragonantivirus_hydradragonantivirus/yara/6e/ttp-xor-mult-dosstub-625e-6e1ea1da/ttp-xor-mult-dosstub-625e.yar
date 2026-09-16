rule TTP_XOR_MULT_DOSStub_625e {
  strings:
    $key_625e = { 36 36 [2] 42 2e [2] 05 2c [2] 42 3d [2] 0c 31 [2] 00 3b [2] 17 30 [2] 0c 7e [2] 31 }

  condition:
    any of them
}