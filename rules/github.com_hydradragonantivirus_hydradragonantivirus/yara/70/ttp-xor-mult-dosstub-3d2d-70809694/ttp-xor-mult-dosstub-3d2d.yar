rule TTP_XOR_MULT_DOSStub_3d2d {
  strings:
    $key_3d2d = { 69 45 [2] 1d 5d [2] 5a 5f [2] 1d 4e [2] 53 42 [2] 5f 48 [2] 48 43 [2] 53 0d [2] 6e }

  condition:
    any of them
}