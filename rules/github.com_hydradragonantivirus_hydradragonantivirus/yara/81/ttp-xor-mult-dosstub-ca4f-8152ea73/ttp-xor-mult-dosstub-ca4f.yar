rule TTP_XOR_MULT_DOSStub_ca4f {
  strings:
    $key_ca4f = { 9e 27 [2] ea 3f [2] ad 3d [2] ea 2c [2] a4 20 [2] a8 2a [2] bf 21 [2] a4 6f [2] 99 }

  condition:
    any of them
}