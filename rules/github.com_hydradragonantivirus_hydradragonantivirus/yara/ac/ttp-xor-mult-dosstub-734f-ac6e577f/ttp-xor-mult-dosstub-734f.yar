rule TTP_XOR_MULT_DOSStub_734f {
  strings:
    $key_734f = { 27 27 [2] 53 3f [2] 14 3d [2] 53 2c [2] 1d 20 [2] 11 2a [2] 06 21 [2] 1d 6f [2] 20 }

  condition:
    any of them
}