rule TTP_XOR_MULT_DOSStub_3d5d {
  strings:
    $key_3d5d = { 69 35 [2] 1d 2d [2] 5a 2f [2] 1d 3e [2] 53 32 [2] 5f 38 [2] 48 33 [2] 53 7d [2] 6e }

  condition:
    any of them
}