rule TTP_XOR_MULT_DOSStub_3740 {
  strings:
    $key_3740 = { 63 28 [2] 17 30 [2] 50 32 [2] 17 23 [2] 59 2f [2] 55 25 [2] 42 2e [2] 59 60 [2] 64 }

  condition:
    any of them
}