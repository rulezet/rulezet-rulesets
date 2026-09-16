rule TTP_XOR_MULT_DOSStub_4a3d {
  strings:
    $key_4a3d = { 1e 55 [2] 6a 4d [2] 2d 4f [2] 6a 5e [2] 24 52 [2] 28 58 [2] 3f 53 [2] 24 1d [2] 19 }

  condition:
    any of them
}