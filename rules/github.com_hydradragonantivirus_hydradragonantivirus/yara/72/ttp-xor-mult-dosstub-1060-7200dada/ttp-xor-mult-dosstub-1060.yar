rule TTP_XOR_MULT_DOSStub_1060 {
  strings:
    $key_1060 = { 44 08 [2] 30 10 [2] 77 12 [2] 30 03 [2] 7e 0f [2] 72 05 [2] 65 0e [2] 7e 40 [2] 43 }

  condition:
    any of them
}