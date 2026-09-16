rule TTP_XOR_MULT_DOSStub_4760 {
  strings:
    $key_4760 = { 13 08 [2] 67 10 [2] 20 12 [2] 67 03 [2] 29 0f [2] 25 05 [2] 32 0e [2] 29 40 [2] 14 }

  condition:
    any of them
}