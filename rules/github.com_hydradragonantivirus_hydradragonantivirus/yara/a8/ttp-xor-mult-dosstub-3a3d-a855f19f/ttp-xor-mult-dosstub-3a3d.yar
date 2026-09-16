rule TTP_XOR_MULT_DOSStub_3a3d {
  strings:
    $key_3a3d = { 6e 55 [2] 1a 4d [2] 5d 4f [2] 1a 5e [2] 54 52 [2] 58 58 [2] 4f 53 [2] 54 1d [2] 69 }

  condition:
    any of them
}