rule TTP_XOR_MULT_DOSStub_71f6 {
  strings:
    $key_71f6 = { 25 9e [2] 51 86 [2] 16 84 [2] 51 95 [2] 1f 99 [2] 13 93 [2] 04 98 [2] 1f d6 [2] 22 }

  condition:
    any of them
}