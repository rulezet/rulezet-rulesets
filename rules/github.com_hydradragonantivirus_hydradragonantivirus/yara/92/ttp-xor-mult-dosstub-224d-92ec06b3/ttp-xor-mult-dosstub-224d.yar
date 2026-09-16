rule TTP_XOR_MULT_DOSStub_224d {
  strings:
    $key_224d = { 76 25 [2] 02 3d [2] 45 3f [2] 02 2e [2] 4c 22 [2] 40 28 [2] 57 23 [2] 4c 6d [2] 71 }

  condition:
    any of them
}