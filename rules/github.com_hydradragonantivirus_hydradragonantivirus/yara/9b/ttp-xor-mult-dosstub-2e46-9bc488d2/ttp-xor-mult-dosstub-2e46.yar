rule TTP_XOR_MULT_DOSStub_2e46 {
  strings:
    $key_2e46 = { 7a 2e [2] 0e 36 [2] 49 34 [2] 0e 25 [2] 40 29 [2] 4c 23 [2] 5b 28 [2] 40 66 [2] 7d }

  condition:
    any of them
}