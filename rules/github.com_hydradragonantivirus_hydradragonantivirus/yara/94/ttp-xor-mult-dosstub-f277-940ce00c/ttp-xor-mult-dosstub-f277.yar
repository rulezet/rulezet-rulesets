rule TTP_XOR_MULT_DOSStub_f277 {
  strings:
    $key_f277 = { a6 1f [2] d2 07 [2] 95 05 [2] d2 14 [2] 9c 18 [2] 90 12 [2] 87 19 [2] 9c 57 [2] a1 }

  condition:
    any of them
}