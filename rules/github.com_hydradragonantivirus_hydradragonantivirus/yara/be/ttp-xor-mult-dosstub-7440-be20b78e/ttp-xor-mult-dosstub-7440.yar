rule TTP_XOR_MULT_DOSStub_7440 {
  strings:
    $key_7440 = { 20 28 [2] 54 30 [2] 13 32 [2] 54 23 [2] 1a 2f [2] 16 25 [2] 01 2e [2] 1a 60 [2] 27 }

  condition:
    any of them
}