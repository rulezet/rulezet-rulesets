rule TTP_XOR_MULT_DOSStub_f148 {
  strings:
    $key_f148 = { a5 20 [2] d1 38 [2] 96 3a [2] d1 2b [2] 9f 27 [2] 93 2d [2] 84 26 [2] 9f 68 [2] a2 }

  condition:
    any of them
}