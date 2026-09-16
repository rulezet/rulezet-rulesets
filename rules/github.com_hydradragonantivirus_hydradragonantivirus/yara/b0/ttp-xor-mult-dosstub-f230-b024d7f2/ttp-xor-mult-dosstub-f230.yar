rule TTP_XOR_MULT_DOSStub_f230 {
  strings:
    $key_f230 = { a6 58 [2] d2 40 [2] 95 42 [2] d2 53 [2] 9c 5f [2] 90 55 [2] 87 5e [2] 9c 10 [2] a1 }

  condition:
    any of them
}