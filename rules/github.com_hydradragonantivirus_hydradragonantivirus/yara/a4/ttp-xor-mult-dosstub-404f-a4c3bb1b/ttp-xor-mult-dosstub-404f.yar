rule TTP_XOR_MULT_DOSStub_404f {
  strings:
    $key_404f = { 14 27 [2] 60 3f [2] 27 3d [2] 60 2c [2] 2e 20 [2] 22 2a [2] 35 21 [2] 2e 6f [2] 13 }

  condition:
    any of them
}