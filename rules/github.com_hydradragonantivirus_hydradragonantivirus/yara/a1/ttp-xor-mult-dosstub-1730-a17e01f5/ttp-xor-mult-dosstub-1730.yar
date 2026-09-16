rule TTP_XOR_MULT_DOSStub_1730 {
  strings:
    $key_1730 = { 43 58 [2] 37 40 [2] 70 42 [2] 37 53 [2] 79 5f [2] 75 55 [2] 62 5e [2] 79 10 [2] 44 }

  condition:
    any of them
}