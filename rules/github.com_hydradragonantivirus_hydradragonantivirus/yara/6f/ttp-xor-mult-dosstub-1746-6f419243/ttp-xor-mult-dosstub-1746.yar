rule TTP_XOR_MULT_DOSStub_1746 {
  strings:
    $key_1746 = { 43 2e [2] 37 36 [2] 70 34 [2] 37 25 [2] 79 29 [2] 75 23 [2] 62 28 [2] 79 66 [2] 44 }

  condition:
    any of them
}