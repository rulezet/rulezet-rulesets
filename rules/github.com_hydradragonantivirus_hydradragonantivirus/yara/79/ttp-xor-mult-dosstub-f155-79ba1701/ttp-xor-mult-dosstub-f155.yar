rule TTP_XOR_MULT_DOSStub_f155 {
  strings:
    $key_f155 = { a5 3d [2] d1 25 [2] 96 27 [2] d1 36 [2] 9f 3a [2] 93 30 [2] 84 3b [2] 9f 75 [2] a2 }

  condition:
    any of them
}