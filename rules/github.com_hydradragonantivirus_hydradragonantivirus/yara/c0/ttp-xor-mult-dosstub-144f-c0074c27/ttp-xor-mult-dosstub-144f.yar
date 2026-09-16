rule TTP_XOR_MULT_DOSStub_144f {
  strings:
    $key_144f = { 40 27 [2] 34 3f [2] 73 3d [2] 34 2c [2] 7a 20 [2] 76 2a [2] 61 21 [2] 7a 6f [2] 47 }

  condition:
    any of them
}