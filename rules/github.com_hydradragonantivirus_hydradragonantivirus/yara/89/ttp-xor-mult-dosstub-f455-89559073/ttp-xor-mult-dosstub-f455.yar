rule TTP_XOR_MULT_DOSStub_f455 {
  strings:
    $key_f455 = { a0 3d [2] d4 25 [2] 93 27 [2] d4 36 [2] 9a 3a [2] 96 30 [2] 81 3b [2] 9a 75 [2] a7 }

  condition:
    any of them
}