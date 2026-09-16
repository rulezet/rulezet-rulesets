rule TTP_XOR_MULT_DOSStub_e34f {
  strings:
    $key_e34f = { b7 27 [2] c3 3f [2] 84 3d [2] c3 2c [2] 8d 20 [2] 81 2a [2] 96 21 [2] 8d 6f [2] b0 }

  condition:
    any of them
}