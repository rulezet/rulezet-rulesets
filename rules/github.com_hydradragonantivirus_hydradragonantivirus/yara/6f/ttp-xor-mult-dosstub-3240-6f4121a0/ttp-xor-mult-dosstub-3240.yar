rule TTP_XOR_MULT_DOSStub_3240 {
  strings:
    $key_3240 = { 66 28 [2] 12 30 [2] 55 32 [2] 12 23 [2] 5c 2f [2] 50 25 [2] 47 2e [2] 5c 60 [2] 61 }

  condition:
    any of them
}