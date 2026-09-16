rule TTP_XOR_MULT_DOSStub_5a4d {
  strings:
    $key_5a4d = { 0e 25 [2] 7a 3d [2] 3d 3f [2] 7a 2e [2] 34 22 [2] 38 28 [2] 2f 23 [2] 34 6d [2] 09 }

  condition:
    any of them
}