rule TTP_XOR_MULT_DOSStub_e652 {
  strings:
    $key_e652 = { b2 3a [2] c6 22 [2] 81 20 [2] c6 31 [2] 88 3d [2] 84 37 [2] 93 3c [2] 88 72 [2] b5 }

  condition:
    any of them
}