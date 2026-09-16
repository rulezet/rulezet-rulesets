rule TTP_XOR_MULT_DOSStub_384d {
  strings:
    $key_384d = { 6c 25 [2] 18 3d [2] 5f 3f [2] 18 2e [2] 56 22 [2] 5a 28 [2] 4d 23 [2] 56 6d [2] 6b }

  condition:
    any of them
}