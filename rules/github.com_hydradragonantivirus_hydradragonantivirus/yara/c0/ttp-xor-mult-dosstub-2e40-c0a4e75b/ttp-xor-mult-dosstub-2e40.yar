rule TTP_XOR_MULT_DOSStub_2e40 {
  strings:
    $key_2e40 = { 7a 28 [2] 0e 30 [2] 49 32 [2] 0e 23 [2] 40 2f [2] 4c 25 [2] 5b 2e [2] 40 60 [2] 7d }

  condition:
    any of them
}