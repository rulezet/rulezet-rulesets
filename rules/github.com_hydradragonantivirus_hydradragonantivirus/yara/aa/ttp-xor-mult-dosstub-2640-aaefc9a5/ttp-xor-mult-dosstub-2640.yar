rule TTP_XOR_MULT_DOSStub_2640 {
  strings:
    $key_2640 = { 72 28 [2] 06 30 [2] 41 32 [2] 06 23 [2] 48 2f [2] 44 25 [2] 53 2e [2] 48 60 [2] 75 }

  condition:
    any of them
}