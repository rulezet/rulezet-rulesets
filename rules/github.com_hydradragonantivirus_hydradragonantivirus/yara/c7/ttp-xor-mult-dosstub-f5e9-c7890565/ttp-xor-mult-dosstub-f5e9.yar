rule TTP_XOR_MULT_DOSStub_f5e9 {
  strings:
    $key_f5e9 = { a1 81 [2] d5 99 [2] 92 9b [2] d5 8a [2] 9b 86 [2] 97 8c [2] 80 87 [2] 9b c9 [2] a6 }

  condition:
    any of them
}