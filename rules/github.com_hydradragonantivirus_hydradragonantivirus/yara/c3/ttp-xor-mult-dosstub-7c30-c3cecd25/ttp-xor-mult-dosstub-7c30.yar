rule TTP_XOR_MULT_DOSStub_7c30 {
  strings:
    $key_7c30 = { 28 58 [2] 5c 40 [2] 1b 42 [2] 5c 53 [2] 12 5f [2] 1e 55 [2] 09 5e [2] 12 10 [2] 2f }

  condition:
    any of them
}