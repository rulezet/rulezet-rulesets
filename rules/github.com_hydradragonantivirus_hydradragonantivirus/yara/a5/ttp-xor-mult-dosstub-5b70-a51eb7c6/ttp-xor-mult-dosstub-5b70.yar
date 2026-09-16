rule TTP_XOR_MULT_DOSStub_5b70 {
  strings:
    $key_5b70 = { 0f 18 [2] 7b 00 [2] 3c 02 [2] 7b 13 [2] 35 1f [2] 39 15 [2] 2e 1e [2] 35 50 [2] 08 }

  condition:
    any of them
}