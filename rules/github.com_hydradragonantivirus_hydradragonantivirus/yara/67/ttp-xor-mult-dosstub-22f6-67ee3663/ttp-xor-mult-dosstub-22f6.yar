rule TTP_XOR_MULT_DOSStub_22f6 {
  strings:
    $key_22f6 = { 76 9e [2] 02 86 [2] 45 84 [2] 02 95 [2] 4c 99 [2] 40 93 [2] 57 98 [2] 4c d6 [2] 71 }

  condition:
    any of them
}