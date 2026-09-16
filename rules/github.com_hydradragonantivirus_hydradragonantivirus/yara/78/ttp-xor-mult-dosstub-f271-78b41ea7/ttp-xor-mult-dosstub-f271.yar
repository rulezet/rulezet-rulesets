rule TTP_XOR_MULT_DOSStub_f271 {
  strings:
    $key_f271 = { a6 19 [2] d2 01 [2] 95 03 [2] d2 12 [2] 9c 1e [2] 90 14 [2] 87 1f [2] 9c 51 [2] a1 }

  condition:
    any of them
}