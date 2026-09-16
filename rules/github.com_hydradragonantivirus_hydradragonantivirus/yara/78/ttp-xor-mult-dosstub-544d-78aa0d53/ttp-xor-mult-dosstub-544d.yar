rule TTP_XOR_MULT_DOSStub_544d {
  strings:
    $key_544d = { 00 25 [2] 74 3d [2] 33 3f [2] 74 2e [2] 3a 22 [2] 36 28 [2] 21 23 [2] 3a 6d [2] 07 }

  condition:
    any of them
}