rule TTP_XOR_MULT_DOSStub_f152 {
  strings:
    $key_f152 = { a5 3a [2] d1 22 [2] 96 20 [2] d1 31 [2] 9f 3d [2] 93 37 [2] 84 3c [2] 9f 72 [2] a2 }

  condition:
    any of them
}