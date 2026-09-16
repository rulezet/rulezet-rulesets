rule TTP_XOR_MULT_DOSStub_5b20 {
  strings:
    $key_5b20 = { 0f 48 [2] 7b 50 [2] 3c 52 [2] 7b 43 [2] 35 4f [2] 39 45 [2] 2e 4e [2] 35 00 [2] 08 }

  condition:
    any of them
}