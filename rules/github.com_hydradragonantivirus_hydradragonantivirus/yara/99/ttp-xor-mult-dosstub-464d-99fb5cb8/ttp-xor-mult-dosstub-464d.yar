rule TTP_XOR_MULT_DOSStub_464d {
  strings:
    $key_464d = { 12 25 [2] 66 3d [2] 21 3f [2] 66 2e [2] 28 22 [2] 24 28 [2] 33 23 [2] 28 6d [2] 15 }

  condition:
    any of them
}