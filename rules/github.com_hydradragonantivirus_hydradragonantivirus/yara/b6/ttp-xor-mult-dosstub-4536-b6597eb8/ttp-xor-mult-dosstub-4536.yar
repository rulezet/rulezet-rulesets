rule TTP_XOR_MULT_DOSStub_4536 {
  strings:
    $key_4536 = { 11 5e [2] 65 46 [2] 22 44 [2] 65 55 [2] 2b 59 [2] 27 53 [2] 30 58 [2] 2b 16 [2] 16 }

  condition:
    any of them
}