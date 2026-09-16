rule TTP_XOR_MULT_DOSStub_3e46 {
  strings:
    $key_3e46 = { 6a 2e [2] 1e 36 [2] 59 34 [2] 1e 25 [2] 50 29 [2] 5c 23 [2] 4b 28 [2] 50 66 [2] 6d }

  condition:
    any of them
}