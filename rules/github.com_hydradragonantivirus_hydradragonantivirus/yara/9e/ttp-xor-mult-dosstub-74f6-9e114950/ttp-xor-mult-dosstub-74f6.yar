rule TTP_XOR_MULT_DOSStub_74f6 {
  strings:
    $key_74f6 = { 20 9e [2] 54 86 [2] 13 84 [2] 54 95 [2] 1a 99 [2] 16 93 [2] 01 98 [2] 1a d6 [2] 27 }

  condition:
    any of them
}