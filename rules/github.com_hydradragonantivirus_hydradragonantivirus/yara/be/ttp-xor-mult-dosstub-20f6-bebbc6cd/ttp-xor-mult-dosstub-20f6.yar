rule TTP_XOR_MULT_DOSStub_20f6 {
  strings:
    $key_20f6 = { 74 9e [2] 00 86 [2] 47 84 [2] 00 95 [2] 4e 99 [2] 42 93 [2] 55 98 [2] 4e d6 [2] 73 }

  condition:
    any of them
}