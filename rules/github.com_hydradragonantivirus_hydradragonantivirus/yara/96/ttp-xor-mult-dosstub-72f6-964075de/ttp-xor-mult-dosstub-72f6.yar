rule TTP_XOR_MULT_DOSStub_72f6 {
  strings:
    $key_72f6 = { 26 9e [2] 52 86 [2] 15 84 [2] 52 95 [2] 1c 99 [2] 10 93 [2] 07 98 [2] 1c d6 [2] 21 }

  condition:
    any of them
}