rule TTP_XOR_MULT_DOSStub_3320 {
  strings:
    $key_3320 = { 67 48 [2] 13 50 [2] 54 52 [2] 13 43 [2] 5d 4f [2] 51 45 [2] 46 4e [2] 5d 00 [2] 60 }

  condition:
    any of them
}