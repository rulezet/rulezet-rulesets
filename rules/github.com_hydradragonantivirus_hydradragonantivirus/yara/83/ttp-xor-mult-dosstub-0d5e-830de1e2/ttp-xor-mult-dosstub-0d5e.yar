rule TTP_XOR_MULT_DOSStub_0d5e {
  strings:
    $key_0d5e = { 59 36 [2] 2d 2e [2] 6a 2c [2] 2d 3d [2] 63 31 [2] 6f 3b [2] 78 30 [2] 63 7e [2] 5e }

  condition:
    any of them
}