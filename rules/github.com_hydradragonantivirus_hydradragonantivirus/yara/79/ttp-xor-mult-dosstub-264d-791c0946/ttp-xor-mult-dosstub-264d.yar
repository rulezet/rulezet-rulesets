rule TTP_XOR_MULT_DOSStub_264d {
  strings:
    $key_264d = { 72 25 [2] 06 3d [2] 41 3f [2] 06 2e [2] 48 22 [2] 44 28 [2] 53 23 [2] 48 6d [2] 75 }

  condition:
    any of them
}