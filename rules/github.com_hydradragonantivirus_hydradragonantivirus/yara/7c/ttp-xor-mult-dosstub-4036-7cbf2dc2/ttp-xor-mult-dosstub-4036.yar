rule TTP_XOR_MULT_DOSStub_4036 {
  strings:
    $key_4036 = { 14 5e [2] 60 46 [2] 27 44 [2] 60 55 [2] 2e 59 [2] 22 53 [2] 35 58 [2] 2e 16 [2] 13 }

  condition:
    any of them
}