rule TTP_XOR_MULT_DOSStub_4650 {
  strings:
    $key_4650 = { 12 38 [2] 66 20 [2] 21 22 [2] 66 33 [2] 28 3f [2] 24 35 [2] 33 3e [2] 28 70 [2] 15 }

  condition:
    any of them
}