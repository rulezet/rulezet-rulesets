rule TTP_XOR_MULT_DOSStub_174d {
  strings:
    $key_174d = { 43 25 [2] 37 3d [2] 70 3f [2] 37 2e [2] 79 22 [2] 75 28 [2] 62 23 [2] 79 6d [2] 44 }

  condition:
    any of them
}