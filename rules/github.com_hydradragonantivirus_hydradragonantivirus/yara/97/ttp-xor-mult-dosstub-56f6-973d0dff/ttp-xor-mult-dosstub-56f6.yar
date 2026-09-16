rule TTP_XOR_MULT_DOSStub_56f6 {
  strings:
    $key_56f6 = { 02 9e [2] 76 86 [2] 31 84 [2] 76 95 [2] 38 99 [2] 34 93 [2] 23 98 [2] 38 d6 [2] 05 }

  condition:
    any of them
}