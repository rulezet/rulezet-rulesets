rule TTP_XOR_MULT_DOSStub_174f {
  strings:
    $key_174f = { 43 27 [2] 37 3f [2] 70 3d [2] 37 2c [2] 79 20 [2] 75 2a [2] 62 21 [2] 79 6f [2] 44 }

  condition:
    any of them
}