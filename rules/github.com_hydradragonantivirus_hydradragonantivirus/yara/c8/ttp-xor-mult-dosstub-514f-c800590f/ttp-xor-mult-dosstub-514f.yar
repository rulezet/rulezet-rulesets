rule TTP_XOR_MULT_DOSStub_514f {
  strings:
    $key_514f = { 05 27 [2] 71 3f [2] 36 3d [2] 71 2c [2] 3f 20 [2] 33 2a [2] 24 21 [2] 3f 6f [2] 02 }

  condition:
    any of them
}