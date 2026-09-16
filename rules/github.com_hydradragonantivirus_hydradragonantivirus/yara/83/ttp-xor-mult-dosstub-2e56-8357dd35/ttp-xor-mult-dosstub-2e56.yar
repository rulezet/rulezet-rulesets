rule TTP_XOR_MULT_DOSStub_2e56 {
  strings:
    $key_2e56 = { 7a 3e [2] 0e 26 [2] 49 24 [2] 0e 35 [2] 40 39 [2] 4c 33 [2] 5b 38 [2] 40 76 [2] 7d }

  condition:
    any of them
}