rule TTP_XOR_MULT_DOSStub_1436 {
  strings:
    $key_1436 = { 40 5e [2] 34 46 [2] 73 44 [2] 34 55 [2] 7a 59 [2] 76 53 [2] 61 58 [2] 7a 16 [2] 47 }

  condition:
    any of them
}