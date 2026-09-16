rule TTP_XOR_MULT_DOSStub_e74f {
  strings:
    $key_e74f = { b3 27 [2] c7 3f [2] 80 3d [2] c7 2c [2] 89 20 [2] 85 2a [2] 92 21 [2] 89 6f [2] b4 }

  condition:
    any of them
}