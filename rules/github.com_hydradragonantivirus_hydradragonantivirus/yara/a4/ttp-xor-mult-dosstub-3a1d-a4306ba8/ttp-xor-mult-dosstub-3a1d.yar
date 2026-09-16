rule TTP_XOR_MULT_DOSStub_3a1d {
  strings:
    $key_3a1d = { 6e 75 [2] 1a 6d [2] 5d 6f [2] 1a 7e [2] 54 72 [2] 58 78 [2] 4f 73 [2] 54 3d [2] 69 }

  condition:
    any of them
}