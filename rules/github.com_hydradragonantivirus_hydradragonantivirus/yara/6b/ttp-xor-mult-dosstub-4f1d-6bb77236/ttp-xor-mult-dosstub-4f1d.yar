rule TTP_XOR_MULT_DOSStub_4f1d {
  strings:
    $key_4f1d = { 1b 75 [2] 6f 6d [2] 28 6f [2] 6f 7e [2] 21 72 [2] 2d 78 [2] 3a 73 [2] 21 3d [2] 1c }

  condition:
    any of them
}