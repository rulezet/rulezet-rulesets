rule TTP_XOR_MULT_DOSStub_204d {
  strings:
    $key_204d = { 74 25 [2] 00 3d [2] 47 3f [2] 00 2e [2] 4e 22 [2] 42 28 [2] 55 23 [2] 4e 6d [2] 73 }

  condition:
    any of them
}