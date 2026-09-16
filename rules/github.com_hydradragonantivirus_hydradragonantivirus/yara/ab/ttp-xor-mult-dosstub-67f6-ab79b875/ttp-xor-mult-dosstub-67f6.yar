rule TTP_XOR_MULT_DOSStub_67f6 {
  strings:
    $key_67f6 = { 33 9e [2] 47 86 [2] 00 84 [2] 47 95 [2] 09 99 [2] 05 93 [2] 12 98 [2] 09 d6 [2] 34 }

  condition:
    any of them
}