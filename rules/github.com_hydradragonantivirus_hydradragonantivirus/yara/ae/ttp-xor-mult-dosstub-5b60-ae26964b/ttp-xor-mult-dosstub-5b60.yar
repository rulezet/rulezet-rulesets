rule TTP_XOR_MULT_DOSStub_5b60 {
  strings:
    $key_5b60 = { 0f 08 [2] 7b 10 [2] 3c 12 [2] 7b 03 [2] 35 0f [2] 39 05 [2] 2e 0e [2] 35 40 [2] 08 }

  condition:
    any of them
}