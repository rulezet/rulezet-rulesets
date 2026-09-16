rule TTP_XOR_MULT_DOSStub_3d4f {
  strings:
    $key_3d4f = { 69 27 [2] 1d 3f [2] 5a 3d [2] 1d 2c [2] 53 20 [2] 5f 2a [2] 48 21 [2] 53 6f [2] 6e }

  condition:
    any of them
}