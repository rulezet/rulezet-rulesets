rule TTP_XOR_MULT_DOSStub_1750 {
  strings:
    $key_1750 = { 43 38 [2] 37 20 [2] 70 22 [2] 37 33 [2] 79 3f [2] 75 35 [2] 62 3e [2] 79 70 [2] 44 }

  condition:
    any of them
}