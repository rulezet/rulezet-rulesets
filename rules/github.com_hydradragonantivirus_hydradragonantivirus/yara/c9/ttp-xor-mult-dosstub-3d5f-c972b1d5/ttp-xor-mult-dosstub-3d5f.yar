rule TTP_XOR_MULT_DOSStub_3d5f {
  strings:
    $key_3d5f = { 69 37 [2] 1d 2f [2] 5a 2d [2] 1d 3c [2] 53 30 [2] 5f 3a [2] 48 31 [2] 53 7f [2] 6e }

  condition:
    any of them
}