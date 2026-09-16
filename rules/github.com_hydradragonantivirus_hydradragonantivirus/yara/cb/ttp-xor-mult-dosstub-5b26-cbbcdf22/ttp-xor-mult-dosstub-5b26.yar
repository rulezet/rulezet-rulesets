rule TTP_XOR_MULT_DOSStub_5b26 {
  strings:
    $key_5b26 = { 0f 4e [2] 7b 56 [2] 3c 54 [2] 7b 45 [2] 35 49 [2] 39 43 [2] 2e 48 [2] 35 06 [2] 08 }

  condition:
    any of them
}