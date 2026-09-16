rule TTP_XOR_MULT_DOSStub_f408 {
  strings:
    $key_f408 = { a0 60 [2] d4 78 [2] 93 7a [2] d4 6b [2] 9a 67 [2] 96 6d [2] 81 66 [2] 9a 28 [2] a7 }

  condition:
    any of them
}