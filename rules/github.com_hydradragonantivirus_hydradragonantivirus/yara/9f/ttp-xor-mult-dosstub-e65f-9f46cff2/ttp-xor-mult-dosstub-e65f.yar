rule TTP_XOR_MULT_DOSStub_e65f {
  strings:
    $key_e65f = { b2 37 [2] c6 2f [2] 81 2d [2] c6 3c [2] 88 30 [2] 84 3a [2] 93 31 [2] 88 7f [2] b5 }

  condition:
    any of them
}