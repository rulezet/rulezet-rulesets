rule TTP_XOR_MULT_DOSStub_434d {
  strings:
    $key_434d = { 17 25 [2] 63 3d [2] 24 3f [2] 63 2e [2] 2d 22 [2] 21 28 [2] 36 23 [2] 2d 6d [2] 10 }

  condition:
    any of them
}