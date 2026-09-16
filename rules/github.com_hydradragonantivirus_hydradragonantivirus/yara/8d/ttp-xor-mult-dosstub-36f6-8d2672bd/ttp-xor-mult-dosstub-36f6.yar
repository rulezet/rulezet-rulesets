rule TTP_XOR_MULT_DOSStub_36f6 {
  strings:
    $key_36f6 = { 62 9e [2] 16 86 [2] 51 84 [2] 16 95 [2] 58 99 [2] 54 93 [2] 43 98 [2] 58 d6 [2] 65 }

  condition:
    any of them
}