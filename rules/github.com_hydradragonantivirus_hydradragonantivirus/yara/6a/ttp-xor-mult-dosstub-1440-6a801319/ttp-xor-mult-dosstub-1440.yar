rule TTP_XOR_MULT_DOSStub_1440 {
  strings:
    $key_1440 = { 40 28 [2] 34 30 [2] 73 32 [2] 34 23 [2] 7a 2f [2] 76 25 [2] 61 2e [2] 7a 60 [2] 47 }

  condition:
    any of them
}