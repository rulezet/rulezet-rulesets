rule TTP_XOR_MULT_DOSStub_5be6 {
  strings:
    $key_5be6 = { 0f 8e [2] 7b 96 [2] 3c 94 [2] 7b 85 [2] 35 89 [2] 39 83 [2] 2e 88 [2] 35 c6 [2] 08 }

  condition:
    any of them
}