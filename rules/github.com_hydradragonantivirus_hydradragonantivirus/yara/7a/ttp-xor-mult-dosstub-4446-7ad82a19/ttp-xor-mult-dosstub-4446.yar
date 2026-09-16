rule TTP_XOR_MULT_DOSStub_4446 {
  strings:
    $key_4446 = { 10 2e [2] 64 36 [2] 23 34 [2] 64 25 [2] 2a 29 [2] 26 23 [2] 31 28 [2] 2a 66 [2] 17 }

  condition:
    any of them
}