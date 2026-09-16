rule TTP_XOR_MULT_DOSStub_4441 {
  strings:
    $key_4441 = { 10 29 [2] 64 31 [2] 23 33 [2] 64 22 [2] 2a 2e [2] 26 24 [2] 31 2f [2] 2a 61 [2] 17 }

  condition:
    any of them
}