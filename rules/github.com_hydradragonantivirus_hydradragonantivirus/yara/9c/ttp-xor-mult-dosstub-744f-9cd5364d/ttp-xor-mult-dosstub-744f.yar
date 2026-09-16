rule TTP_XOR_MULT_DOSStub_744f {
  strings:
    $key_744f = { 20 27 [2] 54 3f [2] 13 3d [2] 54 2c [2] 1a 20 [2] 16 2a [2] 01 21 [2] 1a 6f [2] 27 }

  condition:
    any of them
}