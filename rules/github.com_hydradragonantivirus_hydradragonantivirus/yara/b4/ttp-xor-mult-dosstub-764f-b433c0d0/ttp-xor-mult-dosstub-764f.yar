rule TTP_XOR_MULT_DOSStub_764f {
  strings:
    $key_764f = { 22 27 [2] 56 3f [2] 11 3d [2] 56 2c [2] 18 20 [2] 14 2a [2] 03 21 [2] 18 6f [2] 25 }

  condition:
    any of them
}