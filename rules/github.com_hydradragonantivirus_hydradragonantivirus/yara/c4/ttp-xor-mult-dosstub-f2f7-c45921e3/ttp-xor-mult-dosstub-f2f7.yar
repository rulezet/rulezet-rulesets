rule TTP_XOR_MULT_DOSStub_f2f7 {
  strings:
    $key_f2f7 = { a6 9f [2] d2 87 [2] 95 85 [2] d2 94 [2] 9c 98 [2] 90 92 [2] 87 99 [2] 9c d7 [2] a1 }

  condition:
    any of them
}