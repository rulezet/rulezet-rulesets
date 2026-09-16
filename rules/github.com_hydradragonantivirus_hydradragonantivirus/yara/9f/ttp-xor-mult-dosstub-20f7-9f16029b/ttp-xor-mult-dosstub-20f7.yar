rule TTP_XOR_MULT_DOSStub_20f7 {
  strings:
    $key_20f7 = { 74 9f [2] 00 87 [2] 47 85 [2] 00 94 [2] 4e 98 [2] 42 92 [2] 55 99 [2] 4e d7 [2] 73 }

  condition:
    any of them
}