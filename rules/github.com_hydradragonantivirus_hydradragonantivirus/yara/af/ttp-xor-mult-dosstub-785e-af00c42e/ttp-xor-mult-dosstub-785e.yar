rule TTP_XOR_MULT_DOSStub_785e {
  strings:
    $key_785e = { 2c 36 [2] 58 2e [2] 1f 2c [2] 58 3d [2] 16 31 [2] 1a 3b [2] 0d 30 [2] 16 7e [2] 2b }

  condition:
    any of them
}