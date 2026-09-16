rule TTP_XOR_MULT_DOSStub_45f6 {
  strings:
    $key_45f6 = { 11 9e [2] 65 86 [2] 22 84 [2] 65 95 [2] 2b 99 [2] 27 93 [2] 30 98 [2] 2b d6 [2] 16 }

  condition:
    any of them
}