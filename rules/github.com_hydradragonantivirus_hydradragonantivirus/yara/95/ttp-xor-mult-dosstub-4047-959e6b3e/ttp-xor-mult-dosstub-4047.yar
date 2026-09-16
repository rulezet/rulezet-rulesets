rule TTP_XOR_MULT_DOSStub_4047 {
  strings:
    $key_4047 = { 14 2f [2] 60 37 [2] 27 35 [2] 60 24 [2] 2e 28 [2] 22 22 [2] 35 29 [2] 2e 67 [2] 13 }

  condition:
    any of them
}