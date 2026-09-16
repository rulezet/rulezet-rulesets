rule TTP_XOR_MULT_DOSStub_284f {
  strings:
    $key_284f = { 7c 27 [2] 08 3f [2] 4f 3d [2] 08 2c [2] 46 20 [2] 4a 2a [2] 5d 21 [2] 46 6f [2] 7b }

  condition:
    any of them
}