rule TTP_XOR_MULT_DOSStub_1320 {
  strings:
    $key_1320 = { 47 48 [2] 33 50 [2] 74 52 [2] 33 43 [2] 7d 4f [2] 71 45 [2] 66 4e [2] 7d 00 [2] 40 }

  condition:
    any of them
}