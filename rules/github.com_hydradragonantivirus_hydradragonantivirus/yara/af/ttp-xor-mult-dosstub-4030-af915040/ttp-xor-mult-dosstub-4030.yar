rule TTP_XOR_MULT_DOSStub_4030 {
  strings:
    $key_4030 = { 14 58 [2] 60 40 [2] 27 42 [2] 60 53 [2] 2e 5f [2] 22 55 [2] 35 5e [2] 2e 10 [2] 13 }

  condition:
    any of them
}