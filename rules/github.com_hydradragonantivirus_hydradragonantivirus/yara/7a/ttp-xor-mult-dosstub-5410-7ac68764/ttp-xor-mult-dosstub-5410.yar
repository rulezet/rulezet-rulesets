rule TTP_XOR_MULT_DOSStub_5410 {
  strings:
    $key_5410 = { 00 78 [2] 74 60 [2] 33 62 [2] 74 73 [2] 3a 7f [2] 36 75 [2] 21 7e [2] 3a 30 [2] 07 }

  condition:
    any of them
}