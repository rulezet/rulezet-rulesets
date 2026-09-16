rule TTP_XOR_MULT_DOSStub_4040 {
  strings:
    $key_4040 = { 14 28 [2] 60 30 [2] 27 32 [2] 60 23 [2] 2e 2f [2] 22 25 [2] 35 2e [2] 2e 60 [2] 13 }

  condition:
    any of them
}