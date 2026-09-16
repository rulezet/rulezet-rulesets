rule TTP_XOR_MULT_DOSStub_0740 {
  strings:
    $key_0740 = { 53 28 [2] 27 30 [2] 60 32 [2] 27 23 [2] 69 2f [2] 65 25 [2] 72 2e [2] 69 60 [2] 54 }

  condition:
    any of them
}