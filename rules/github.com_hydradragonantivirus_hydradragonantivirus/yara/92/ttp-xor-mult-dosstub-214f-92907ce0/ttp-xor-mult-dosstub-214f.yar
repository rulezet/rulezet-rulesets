rule TTP_XOR_MULT_DOSStub_214f {
  strings:
    $key_214f = { 75 27 [2] 01 3f [2] 46 3d [2] 01 2c [2] 4f 20 [2] 43 2a [2] 54 21 [2] 4f 6f [2] 72 }

  condition:
    any of them
}