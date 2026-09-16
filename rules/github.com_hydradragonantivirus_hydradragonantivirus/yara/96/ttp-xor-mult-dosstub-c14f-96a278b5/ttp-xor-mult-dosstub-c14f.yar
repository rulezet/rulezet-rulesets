rule TTP_XOR_MULT_DOSStub_c14f {
  strings:
    $key_c14f = { 95 27 [2] e1 3f [2] a6 3d [2] e1 2c [2] af 20 [2] a3 2a [2] b4 21 [2] af 6f [2] 92 }

  condition:
    any of them
}