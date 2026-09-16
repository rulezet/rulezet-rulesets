rule TTP_XOR_MULT_DOSStub_c64f {
  strings:
    $key_c64f = { 92 27 [2] e6 3f [2] a1 3d [2] e6 2c [2] a8 20 [2] a4 2a [2] b3 21 [2] a8 6f [2] 95 }

  condition:
    any of them
}