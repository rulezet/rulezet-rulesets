rule TTP_XOR_MULT_DOSStub_f246 {
  strings:
    $key_f246 = { a6 2e [2] d2 36 [2] 95 34 [2] d2 25 [2] 9c 29 [2] 90 23 [2] 87 28 [2] 9c 66 [2] a1 }

  condition:
    any of them
}