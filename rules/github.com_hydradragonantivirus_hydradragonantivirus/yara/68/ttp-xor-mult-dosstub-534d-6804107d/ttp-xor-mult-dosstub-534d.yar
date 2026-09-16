rule TTP_XOR_MULT_DOSStub_534d {
  strings:
    $key_534d = { 07 25 [2] 73 3d [2] 34 3f [2] 73 2e [2] 3d 22 [2] 31 28 [2] 26 23 [2] 3d 6d [2] 00 }

  condition:
    any of them
}