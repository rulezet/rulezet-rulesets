rule TTP_XOR_MULT_DOSStub_2040 {
  strings:
    $key_2040 = { 74 28 [2] 00 30 [2] 47 32 [2] 00 23 [2] 4e 2f [2] 42 25 [2] 55 2e [2] 4e 60 [2] 73 }

  condition:
    any of them
}