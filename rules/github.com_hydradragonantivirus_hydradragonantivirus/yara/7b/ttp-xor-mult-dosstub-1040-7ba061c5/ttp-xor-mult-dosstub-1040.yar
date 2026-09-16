rule TTP_XOR_MULT_DOSStub_1040 {
  strings:
    $key_1040 = { 44 28 [2] 30 30 [2] 77 32 [2] 30 23 [2] 7e 2f [2] 72 25 [2] 65 2e [2] 7e 60 [2] 43 }

  condition:
    any of them
}