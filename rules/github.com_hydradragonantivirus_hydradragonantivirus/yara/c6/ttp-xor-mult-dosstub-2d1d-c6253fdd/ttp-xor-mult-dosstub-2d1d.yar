rule TTP_XOR_MULT_DOSStub_2d1d {
  strings:
    $key_2d1d = { 79 75 [2] 0d 6d [2] 4a 6f [2] 0d 7e [2] 43 72 [2] 4f 78 [2] 58 73 [2] 43 3d [2] 7e }

  condition:
    any of them
}