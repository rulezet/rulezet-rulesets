rule TTP_XOR_MULT_DOSStub_2e20 {
  strings:
    $key_2e20 = { 7a 48 [2] 0e 50 [2] 49 52 [2] 0e 43 [2] 40 4f [2] 4c 45 [2] 5b 4e [2] 40 00 [2] 7d }

  condition:
    any of them
}