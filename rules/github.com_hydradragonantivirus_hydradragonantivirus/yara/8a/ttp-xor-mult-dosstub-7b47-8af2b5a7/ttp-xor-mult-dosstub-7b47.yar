rule TTP_XOR_MULT_DOSStub_7b47 {
  strings:
    $key_7b47 = { 2f 2f [2] 5b 37 [2] 1c 35 [2] 5b 24 [2] 15 28 [2] 19 22 [2] 0e 29 [2] 15 67 [2] 28 }

  condition:
    any of them
}