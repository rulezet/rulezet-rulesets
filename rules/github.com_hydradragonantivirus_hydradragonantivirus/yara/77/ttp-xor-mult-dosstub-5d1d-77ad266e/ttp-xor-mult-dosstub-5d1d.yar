rule TTP_XOR_MULT_DOSStub_5d1d {
  strings:
    $key_5d1d = { 09 75 [2] 7d 6d [2] 3a 6f [2] 7d 7e [2] 33 72 [2] 3f 78 [2] 28 73 [2] 33 3d [2] 0e }

  condition:
    any of them
}