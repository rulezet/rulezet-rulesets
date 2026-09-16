rule TTP_XOR_MULT_DOSStub_c34f {
  strings:
    $key_c34f = { 97 27 [2] e3 3f [2] a4 3d [2] e3 2c [2] ad 20 [2] a1 2a [2] b6 21 [2] ad 6f [2] 90 }

  condition:
    any of them
}