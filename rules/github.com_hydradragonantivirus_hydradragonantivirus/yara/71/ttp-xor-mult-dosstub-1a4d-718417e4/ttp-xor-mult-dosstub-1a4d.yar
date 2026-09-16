rule TTP_XOR_MULT_DOSStub_1a4d {
  strings:
    $key_1a4d = { 4e 25 [2] 3a 3d [2] 7d 3f [2] 3a 2e [2] 74 22 [2] 78 28 [2] 6f 23 [2] 74 6d [2] 49 }

  condition:
    any of them
}