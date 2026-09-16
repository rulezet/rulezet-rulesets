rule TTP_XOR_MULT_DOSStub_04f6 {
  strings:
    $key_04f6 = { 50 9e [2] 24 86 [2] 63 84 [2] 24 95 [2] 6a 99 [2] 66 93 [2] 71 98 [2] 6a d6 [2] 57 }

  condition:
    any of them
}