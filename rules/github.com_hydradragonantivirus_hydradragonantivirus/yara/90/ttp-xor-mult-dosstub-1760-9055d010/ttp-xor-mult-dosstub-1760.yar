rule TTP_XOR_MULT_DOSStub_1760 {
  strings:
    $key_1760 = { 43 08 [2] 37 10 [2] 70 12 [2] 37 03 [2] 79 0f [2] 75 05 [2] 62 0e [2] 79 40 [2] 44 }

  condition:
    any of them
}