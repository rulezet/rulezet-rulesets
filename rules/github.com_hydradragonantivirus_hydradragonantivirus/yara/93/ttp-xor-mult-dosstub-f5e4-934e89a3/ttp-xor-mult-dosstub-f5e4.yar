rule TTP_XOR_MULT_DOSStub_f5e4 {
  strings:
    $key_f5e4 = { a1 8c [2] d5 94 [2] 92 96 [2] d5 87 [2] 9b 8b [2] 97 81 [2] 80 8a [2] 9b c4 [2] a6 }

  condition:
    any of them
}