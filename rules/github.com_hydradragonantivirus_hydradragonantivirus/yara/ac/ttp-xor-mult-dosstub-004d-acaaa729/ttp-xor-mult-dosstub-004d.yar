rule TTP_XOR_MULT_DOSStub_004d {
  strings:
    $key_004d = { 54 25 [2] 20 3d [2] 67 3f [2] 20 2e [2] 6e 22 [2] 62 28 [2] 75 23 [2] 6e 6d [2] 53 }

  condition:
    any of them
}