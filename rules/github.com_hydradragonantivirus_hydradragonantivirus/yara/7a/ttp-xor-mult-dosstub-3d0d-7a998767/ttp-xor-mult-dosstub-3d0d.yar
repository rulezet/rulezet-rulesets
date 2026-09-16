rule TTP_XOR_MULT_DOSStub_3d0d {
  strings:
    $key_3d0d = { 69 65 [2] 1d 7d [2] 5a 7f [2] 1d 6e [2] 53 62 [2] 5f 68 [2] 48 63 [2] 53 2d [2] 6e }

  condition:
    any of them
}