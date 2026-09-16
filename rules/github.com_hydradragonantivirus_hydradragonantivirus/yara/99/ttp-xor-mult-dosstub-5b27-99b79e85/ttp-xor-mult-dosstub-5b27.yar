rule TTP_XOR_MULT_DOSStub_5b27 {
  strings:
    $key_5b27 = { 0f 4f [2] 7b 57 [2] 3c 55 [2] 7b 44 [2] 35 48 [2] 39 42 [2] 2e 49 [2] 35 07 [2] 08 }

  condition:
    any of them
}