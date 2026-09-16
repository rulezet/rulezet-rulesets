rule TTP_XOR_MULT_DOSStub_f290 {
  strings:
    $key_f290 = { a6 f8 [2] d2 e0 [2] 95 e2 [2] d2 f3 [2] 9c ff [2] 90 f5 [2] 87 fe [2] 9c b0 [2] a1 }

  condition:
    any of them
}