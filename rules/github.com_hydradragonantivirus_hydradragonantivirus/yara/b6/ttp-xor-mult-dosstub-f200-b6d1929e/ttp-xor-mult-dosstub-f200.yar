rule TTP_XOR_MULT_DOSStub_f200 {
  strings:
    $key_f200 = { a6 68 [2] d2 70 [2] 95 72 [2] d2 63 [2] 9c 6f [2] 90 65 [2] 87 6e [2] 9c 20 [2] a1 }

  condition:
    any of them
}