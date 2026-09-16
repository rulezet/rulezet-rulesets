rule TTP_XOR_MULT_DOSStub_7030 {
  strings:
    $key_7030 = { 24 58 [2] 50 40 [2] 17 42 [2] 50 53 [2] 1e 5f [2] 12 55 [2] 05 5e [2] 1e 10 [2] 23 }

  condition:
    any of them
}