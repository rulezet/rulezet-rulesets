rule TTP_XOR_MULT_DOSStub_414d {
  strings:
    $key_414d = { 15 25 [2] 61 3d [2] 26 3f [2] 61 2e [2] 2f 22 [2] 23 28 [2] 34 23 [2] 2f 6d [2] 12 }

  condition:
    any of them
}