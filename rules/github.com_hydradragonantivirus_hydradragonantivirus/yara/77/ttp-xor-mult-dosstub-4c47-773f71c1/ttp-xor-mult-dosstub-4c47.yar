rule TTP_XOR_MULT_DOSStub_4c47 {
  strings:
    $key_4c47 = { 18 2f [2] 6c 37 [2] 2b 35 [2] 6c 24 [2] 22 28 [2] 2e 22 [2] 39 29 [2] 22 67 [2] 1f }

  condition:
    any of them
}