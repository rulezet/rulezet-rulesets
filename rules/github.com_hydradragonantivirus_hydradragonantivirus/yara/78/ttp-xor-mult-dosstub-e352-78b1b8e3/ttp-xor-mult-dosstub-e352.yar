rule TTP_XOR_MULT_DOSStub_e352 {
  strings:
    $key_e352 = { b7 3a [2] c3 22 [2] 84 20 [2] c3 31 [2] 8d 3d [2] 81 37 [2] 96 3c [2] 8d 72 [2] b0 }

  condition:
    any of them
}