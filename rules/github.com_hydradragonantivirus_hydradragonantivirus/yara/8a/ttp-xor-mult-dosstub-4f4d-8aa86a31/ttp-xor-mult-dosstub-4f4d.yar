rule TTP_XOR_MULT_DOSStub_4f4d {
  strings:
    $key_4f4d = { 1b 25 [2] 6f 3d [2] 28 3f [2] 6f 2e [2] 21 22 [2] 2d 28 [2] 3a 23 [2] 21 6d [2] 1c }

  condition:
    any of them
}