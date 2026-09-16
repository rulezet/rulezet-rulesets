rule TTP_XOR_MULT_DOSStub_e45f {
  strings:
    $key_e45f = { b0 37 [2] c4 2f [2] 83 2d [2] c4 3c [2] 8a 30 [2] 86 3a [2] 91 31 [2] 8a 7f [2] b7 }

  condition:
    any of them
}