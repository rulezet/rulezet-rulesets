rule TTP_XOR_MULT_DOSStub_f7f1 {
  strings:
    $key_f7f1 = { a3 99 [2] d7 81 [2] 90 83 [2] d7 92 [2] 99 9e [2] 95 94 [2] 82 9f [2] 99 d1 [2] a4 }

  condition:
    any of them
}