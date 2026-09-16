rule TTP_XOR_MULT_DOSStub_f145 {
  strings:
    $key_f145 = { a5 2d [2] d1 35 [2] 96 37 [2] d1 26 [2] 9f 2a [2] 93 20 [2] 84 2b [2] 9f 65 [2] a2 }

  condition:
    any of them
}