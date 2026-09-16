rule TTP_XOR_MULT_DOSStub_1450 {
  strings:
    $key_1450 = { 40 38 [2] 34 20 [2] 73 22 [2] 34 33 [2] 7a 3f [2] 76 35 [2] 61 3e [2] 7a 70 [2] 47 }

  condition:
    any of them
}