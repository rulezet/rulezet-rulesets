rule TTP_XOR_MULT_DOSStub_537d {
  strings:
    $key_537d = { 07 15 [2] 73 0d [2] 34 0f [2] 73 1e [2] 3d 12 [2] 31 18 [2] 26 13 [2] 3d 5d [2] 00 }

  condition:
    any of them
}