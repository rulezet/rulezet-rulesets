rule TTP_XOR_MULT_DOSStub_404d {
  strings:
    $key_404d = { 14 25 [2] 60 3d [2] 27 3f [2] 60 2e [2] 2e 22 [2] 22 28 [2] 35 23 [2] 2e 6d [2] 13 }

  condition:
    any of them
}