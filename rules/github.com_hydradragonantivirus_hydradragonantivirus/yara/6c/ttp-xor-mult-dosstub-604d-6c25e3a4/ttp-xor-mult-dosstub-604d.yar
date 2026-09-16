rule TTP_XOR_MULT_DOSStub_604d {
  strings:
    $key_604d = { 34 25 [2] 40 3d [2] 07 3f [2] 40 2e [2] 0e 22 [2] 02 28 [2] 15 23 [2] 0e 6d [2] 33 }

  condition:
    any of them
}