rule TTP_XOR_MULT_DOSStub_7c47 {
  strings:
    $key_7c47 = { 28 2f [2] 5c 37 [2] 1b 35 [2] 5c 24 [2] 12 28 [2] 1e 22 [2] 09 29 [2] 12 67 [2] 2f }

  condition:
    any of them
}