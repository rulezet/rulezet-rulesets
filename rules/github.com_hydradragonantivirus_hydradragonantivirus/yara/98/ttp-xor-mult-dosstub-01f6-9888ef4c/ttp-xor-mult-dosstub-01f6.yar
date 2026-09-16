rule TTP_XOR_MULT_DOSStub_01f6 {
  strings:
    $key_01f6 = { 55 9e [2] 21 86 [2] 66 84 [2] 21 95 [2] 6f 99 [2] 63 93 [2] 74 98 [2] 6f d6 [2] 52 }

  condition:
    any of them
}