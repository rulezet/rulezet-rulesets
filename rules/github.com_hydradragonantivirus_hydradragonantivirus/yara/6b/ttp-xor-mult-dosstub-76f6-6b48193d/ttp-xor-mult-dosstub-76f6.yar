rule TTP_XOR_MULT_DOSStub_76f6 {
  strings:
    $key_76f6 = { 22 9e [2] 56 86 [2] 11 84 [2] 56 95 [2] 18 99 [2] 14 93 [2] 03 98 [2] 18 d6 [2] 25 }

  condition:
    any of them
}