rule TTP_XOR_MULT_DOSStub_55f6 {
  strings:
    $key_55f6 = { 01 9e [2] 75 86 [2] 32 84 [2] 75 95 [2] 3b 99 [2] 37 93 [2] 20 98 [2] 3b d6 [2] 06 }

  condition:
    any of them
}