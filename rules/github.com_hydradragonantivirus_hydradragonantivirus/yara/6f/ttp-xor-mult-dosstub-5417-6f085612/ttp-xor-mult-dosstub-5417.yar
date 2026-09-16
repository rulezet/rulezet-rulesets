rule TTP_XOR_MULT_DOSStub_5417 {
  strings:
    $key_5417 = { 00 7f [2] 74 67 [2] 33 65 [2] 74 74 [2] 3a 78 [2] 36 72 [2] 21 79 [2] 3a 37 [2] 07 }

  condition:
    any of them
}