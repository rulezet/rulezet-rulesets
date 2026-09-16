rule TTP_XOR_MULT_DOSStub_644f {
  strings:
    $key_644f = { 30 27 [2] 44 3f [2] 03 3d [2] 44 2c [2] 0a 20 [2] 06 2a [2] 11 21 [2] 0a 6f [2] 37 }

  condition:
    any of them
}