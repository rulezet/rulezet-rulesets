rule TTP_XOR_MULT_DOSStub_4f3d {
  strings:
    $key_4f3d = { 1b 55 [2] 6f 4d [2] 28 4f [2] 6f 5e [2] 21 52 [2] 2d 58 [2] 3a 53 [2] 21 1d [2] 1c }

  condition:
    any of them
}