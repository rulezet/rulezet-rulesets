rule TTP_XOR_MULT_DOSStub_50f6 {
  strings:
    $key_50f6 = { 04 9e [2] 70 86 [2] 37 84 [2] 70 95 [2] 3e 99 [2] 32 93 [2] 25 98 [2] 3e d6 [2] 03 }

  condition:
    any of them
}