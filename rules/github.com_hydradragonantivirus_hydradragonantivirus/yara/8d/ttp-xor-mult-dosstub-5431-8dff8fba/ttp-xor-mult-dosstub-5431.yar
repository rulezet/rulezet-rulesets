rule TTP_XOR_MULT_DOSStub_5431 {
  strings:
    $key_5431 = { 00 59 [2] 74 41 [2] 33 43 [2] 74 52 [2] 3a 5e [2] 36 54 [2] 21 5f [2] 3a 11 [2] 07 }

  condition:
    any of them
}