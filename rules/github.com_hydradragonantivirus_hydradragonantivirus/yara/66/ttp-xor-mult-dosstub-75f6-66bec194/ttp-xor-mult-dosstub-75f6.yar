rule TTP_XOR_MULT_DOSStub_75f6 {
  strings:
    $key_75f6 = { 21 9e [2] 55 86 [2] 12 84 [2] 55 95 [2] 1b 99 [2] 17 93 [2] 00 98 [2] 1b d6 [2] 26 }

  condition:
    any of them
}