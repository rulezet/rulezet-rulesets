rule TTP_XOR_MULT_DOSStub_074f {
  strings:
    $key_074f = { 53 27 [2] 27 3f [2] 60 3d [2] 27 2c [2] 69 20 [2] 65 2a [2] 72 21 [2] 69 6f [2] 54 }

  condition:
    any of them
}