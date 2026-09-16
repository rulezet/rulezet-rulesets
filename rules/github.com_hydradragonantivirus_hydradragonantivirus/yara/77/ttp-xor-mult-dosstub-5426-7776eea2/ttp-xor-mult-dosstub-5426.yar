rule TTP_XOR_MULT_DOSStub_5426 {
  strings:
    $key_5426 = { 00 4e [2] 74 56 [2] 33 54 [2] 74 45 [2] 3a 49 [2] 36 43 [2] 21 48 [2] 3a 06 [2] 07 }

  condition:
    any of them
}