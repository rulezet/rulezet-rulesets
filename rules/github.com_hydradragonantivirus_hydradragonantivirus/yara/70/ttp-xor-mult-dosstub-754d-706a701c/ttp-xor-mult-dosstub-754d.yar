rule TTP_XOR_MULT_DOSStub_754d {
  strings:
    $key_754d = { 21 25 [2] 55 3d [2] 12 3f [2] 55 2e [2] 1b 22 [2] 17 28 [2] 00 23 [2] 1b 6d [2] 26 }

  condition:
    any of them
}