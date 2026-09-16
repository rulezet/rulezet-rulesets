rule TTP_XOR_MULT_DOSStub_2540 {
  strings:
    $key_2540 = { 71 28 [2] 05 30 [2] 42 32 [2] 05 23 [2] 4b 2f [2] 47 25 [2] 50 2e [2] 4b 60 [2] 76 }

  condition:
    any of them
}