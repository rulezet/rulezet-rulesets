rule TTP_XOR_MULT_DOSStub_30f7 {
  strings:
    $key_30f7 = { 64 9f [2] 10 87 [2] 57 85 [2] 10 94 [2] 5e 98 [2] 52 92 [2] 45 99 [2] 5e d7 [2] 63 }

  condition:
    any of them
}