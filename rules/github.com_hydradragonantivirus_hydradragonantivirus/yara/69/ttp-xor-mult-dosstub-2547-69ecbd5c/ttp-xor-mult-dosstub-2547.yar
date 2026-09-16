rule TTP_XOR_MULT_DOSStub_2547 {
  strings:
    $key_2547 = { 71 2f [2] 05 37 [2] 42 35 [2] 05 24 [2] 4b 28 [2] 47 22 [2] 50 29 [2] 4b 67 [2] 76 }

  condition:
    any of them
}