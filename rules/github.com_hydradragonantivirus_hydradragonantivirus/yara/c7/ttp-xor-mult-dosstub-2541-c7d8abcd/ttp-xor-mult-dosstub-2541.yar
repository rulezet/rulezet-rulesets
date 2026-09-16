rule TTP_XOR_MULT_DOSStub_2541 {
  strings:
    $key_2541 = { 71 29 [2] 05 31 [2] 42 33 [2] 05 22 [2] 4b 2e [2] 47 24 [2] 50 2f [2] 4b 61 [2] 76 }

  condition:
    any of them
}