rule TTP_XOR_MULT_DOSStub_20f1 {
  strings:
    $key_20f1 = { 74 99 [2] 00 81 [2] 47 83 [2] 00 92 [2] 4e 9e [2] 42 94 [2] 55 9f [2] 4e d1 [2] 73 }

  condition:
    any of them
}