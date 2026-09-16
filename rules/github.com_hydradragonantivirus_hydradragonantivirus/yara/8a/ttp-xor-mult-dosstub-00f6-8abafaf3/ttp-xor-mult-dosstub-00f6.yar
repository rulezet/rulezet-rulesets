rule TTP_XOR_MULT_DOSStub_00f6 {
  strings:
    $key_00f6 = { 54 9e [2] 20 86 [2] 67 84 [2] 20 95 [2] 6e 99 [2] 62 93 [2] 75 98 [2] 6e d6 [2] 53 }

  condition:
    any of them
}