rule TTP_XOR_MULT_DOSStub_1d0d {
  strings:
    $key_1d0d = { 49 65 [2] 3d 7d [2] 7a 7f [2] 3d 6e [2] 73 62 [2] 7f 68 [2] 68 63 [2] 73 2d [2] 4e }

  condition:
    any of them
}