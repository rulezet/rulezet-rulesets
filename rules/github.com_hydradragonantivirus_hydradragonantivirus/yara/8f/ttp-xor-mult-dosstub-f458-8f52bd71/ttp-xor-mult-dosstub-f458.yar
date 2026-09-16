rule TTP_XOR_MULT_DOSStub_f458 {
  strings:
    $key_f458 = { a0 30 [2] d4 28 [2] 93 2a [2] d4 3b [2] 9a 37 [2] 96 3d [2] 81 36 [2] 9a 78 [2] a7 }

  condition:
    any of them
}