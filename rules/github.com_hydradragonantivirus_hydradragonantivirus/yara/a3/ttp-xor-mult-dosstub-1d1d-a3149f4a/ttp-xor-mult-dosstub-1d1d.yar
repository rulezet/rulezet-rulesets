rule TTP_XOR_MULT_DOSStub_1d1d {
  strings:
    $key_1d1d = { 49 75 [2] 3d 6d [2] 7a 6f [2] 3d 7e [2] 73 72 [2] 7f 78 [2] 68 73 [2] 73 3d [2] 4e }

  condition:
    any of them
}