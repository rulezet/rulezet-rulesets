rule TTP_XOR_MULT_DOSStub_7c40 {
  strings:
    $key_7c40 = { 28 28 [2] 5c 30 [2] 1b 32 [2] 5c 23 [2] 12 2f [2] 1e 25 [2] 09 2e [2] 12 60 [2] 2f }

  condition:
    any of them
}