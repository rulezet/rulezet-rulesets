rule TTP_XOR_MULT_DOSStub_2440 {
  strings:
    $key_2440 = { 70 28 [2] 04 30 [2] 43 32 [2] 04 23 [2] 4a 2f [2] 46 25 [2] 51 2e [2] 4a 60 [2] 77 }

  condition:
    any of them
}