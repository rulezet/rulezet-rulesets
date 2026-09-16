rule TTP_XOR_MULT_DOSStub_16f6 {
  strings:
    $key_16f6 = { 42 9e [2] 36 86 [2] 71 84 [2] 36 95 [2] 78 99 [2] 74 93 [2] 63 98 [2] 78 d6 [2] 45 }

  condition:
    any of them
}