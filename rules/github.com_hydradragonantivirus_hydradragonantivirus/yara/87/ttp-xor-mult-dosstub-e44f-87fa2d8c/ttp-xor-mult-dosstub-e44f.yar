rule TTP_XOR_MULT_DOSStub_e44f {
  strings:
    $key_e44f = { b0 27 [2] c4 3f [2] 83 3d [2] c4 2c [2] 8a 20 [2] 86 2a [2] 91 21 [2] 8a 6f [2] b7 }

  condition:
    any of them
}