rule TTP_XOR_MULT_DOSStub_f7e4 {
  strings:
    $key_f7e4 = { a3 8c [2] d7 94 [2] 90 96 [2] d7 87 [2] 99 8b [2] 95 81 [2] 82 8a [2] 99 c4 [2] a4 }

  condition:
    any of them
}