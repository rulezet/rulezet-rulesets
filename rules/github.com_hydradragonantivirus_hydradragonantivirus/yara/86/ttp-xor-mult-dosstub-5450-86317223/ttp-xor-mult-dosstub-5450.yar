rule TTP_XOR_MULT_DOSStub_5450 {
  strings:
    $key_5450 = { 00 38 [2] 74 20 [2] 33 22 [2] 74 33 [2] 3a 3f [2] 36 35 [2] 21 3e [2] 3a 70 [2] 07 }

  condition:
    any of them
}