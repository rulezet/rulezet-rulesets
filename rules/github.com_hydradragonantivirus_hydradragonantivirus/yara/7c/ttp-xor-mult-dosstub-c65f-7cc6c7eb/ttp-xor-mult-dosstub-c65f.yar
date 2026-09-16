rule TTP_XOR_MULT_DOSStub_c65f {
  strings:
    $key_c65f = { 92 37 [2] e6 2f [2] a1 2d [2] e6 3c [2] a8 30 [2] a4 3a [2] b3 31 [2] a8 7f [2] 95 }

  condition:
    any of them
}