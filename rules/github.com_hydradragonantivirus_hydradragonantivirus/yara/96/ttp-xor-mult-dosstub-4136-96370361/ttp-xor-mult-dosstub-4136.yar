rule TTP_XOR_MULT_DOSStub_4136 {
  strings:
    $key_4136 = { 15 5e [2] 61 46 [2] 26 44 [2] 61 55 [2] 2f 59 [2] 23 53 [2] 34 58 [2] 2f 16 [2] 12 }

  condition:
    any of them
}