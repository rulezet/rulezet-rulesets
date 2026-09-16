rule TTP_XOR_MULT_DOSStub_60f7 {
  strings:
    $key_60f7 = { 34 9f [2] 40 87 [2] 07 85 [2] 40 94 [2] 0e 98 [2] 02 92 [2] 15 99 [2] 0e d7 [2] 33 }

  condition:
    any of them
}