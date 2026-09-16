rule TTP_XOR_MULT_DOSStub_c04f {
  strings:
    $key_c04f = { 94 27 [2] e0 3f [2] a7 3d [2] e0 2c [2] ae 20 [2] a2 2a [2] b5 21 [2] ae 6f [2] 93 }

  condition:
    any of them
}