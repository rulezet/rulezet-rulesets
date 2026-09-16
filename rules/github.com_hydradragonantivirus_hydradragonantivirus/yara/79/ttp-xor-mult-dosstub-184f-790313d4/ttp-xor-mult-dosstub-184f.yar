rule TTP_XOR_MULT_DOSStub_184f {
  strings:
    $key_184f = { 4c 27 [2] 38 3f [2] 7f 3d [2] 38 2c [2] 76 20 [2] 7a 2a [2] 6d 21 [2] 76 6f [2] 4b }

  condition:
    any of them
}