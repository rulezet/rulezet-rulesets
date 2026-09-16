rule TTP_XOR_MULT_DOSStub_3046 {
  strings:
    $key_3046 = { 64 2e [2] 10 36 [2] 57 34 [2] 10 25 [2] 5e 29 [2] 52 23 [2] 45 28 [2] 5e 66 [2] 63 }

  condition:
    any of them
}