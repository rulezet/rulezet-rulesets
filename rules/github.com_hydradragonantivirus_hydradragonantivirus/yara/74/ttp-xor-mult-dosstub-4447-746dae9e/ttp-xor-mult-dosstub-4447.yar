rule TTP_XOR_MULT_DOSStub_4447 {
  strings:
    $key_4447 = { 10 2f [2] 64 37 [2] 23 35 [2] 64 24 [2] 2a 28 [2] 26 22 [2] 31 29 [2] 2a 67 [2] 17 }

  condition:
    any of them
}