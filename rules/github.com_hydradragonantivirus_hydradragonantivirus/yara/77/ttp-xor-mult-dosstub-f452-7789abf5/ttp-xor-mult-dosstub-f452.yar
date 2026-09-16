rule TTP_XOR_MULT_DOSStub_f452 {
  strings:
    $key_f452 = { a0 3a [2] d4 22 [2] 93 20 [2] d4 31 [2] 9a 3d [2] 96 37 [2] 81 3c [2] 9a 72 [2] a7 }

  condition:
    any of them
}