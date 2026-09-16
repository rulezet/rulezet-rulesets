rule TTP_XOR_MULT_DOSStub_f1e9 {
  strings:
    $key_f1e9 = { a5 81 [2] d1 99 [2] 96 9b [2] d1 8a [2] 9f 86 [2] 93 8c [2] 84 87 [2] 9f c9 [2] a2 }

  condition:
    any of them
}