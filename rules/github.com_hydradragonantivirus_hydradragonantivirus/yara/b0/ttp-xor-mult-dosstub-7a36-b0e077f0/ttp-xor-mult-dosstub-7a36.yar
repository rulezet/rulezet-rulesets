rule TTP_XOR_MULT_DOSStub_7a36 {
  strings:
    $key_7a36 = { 2e 5e [2] 5a 46 [2] 1d 44 [2] 5a 55 [2] 14 59 [2] 18 53 [2] 0f 58 [2] 14 16 [2] 29 }

  condition:
    any of them
}