rule TTP_XOR_MULT_DOSStub_7a4d {
  strings:
    $key_7a4d = { 2e 25 [2] 5a 3d [2] 1d 3f [2] 5a 2e [2] 14 22 [2] 18 28 [2] 0f 23 [2] 14 6d [2] 29 }

  condition:
    any of them
}