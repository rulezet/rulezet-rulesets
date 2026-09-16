rule TTP_XOR_MULT_DOSStub_f1e4 {
  strings:
    $key_f1e4 = { a5 8c [2] d1 94 [2] 96 96 [2] d1 87 [2] 9f 8b [2] 93 81 [2] 84 8a [2] 9f c4 [2] a2 }

  condition:
    any of them
}