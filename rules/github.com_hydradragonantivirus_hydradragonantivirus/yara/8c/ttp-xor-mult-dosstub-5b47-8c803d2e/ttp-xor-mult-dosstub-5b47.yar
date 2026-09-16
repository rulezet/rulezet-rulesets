rule TTP_XOR_MULT_DOSStub_5b47 {
  strings:
    $key_5b47 = { 0f 2f [2] 7b 37 [2] 3c 35 [2] 7b 24 [2] 35 28 [2] 39 22 [2] 2e 29 [2] 35 67 [2] 08 }

  condition:
    any of them
}