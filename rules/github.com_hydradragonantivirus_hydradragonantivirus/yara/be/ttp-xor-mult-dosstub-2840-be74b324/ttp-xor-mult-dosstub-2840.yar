rule TTP_XOR_MULT_DOSStub_2840 {
  strings:
    $key_2840 = { 7c 28 [2] 08 30 [2] 4f 32 [2] 08 23 [2] 46 2f [2] 4a 25 [2] 5d 2e [2] 46 60 [2] 7b }

  condition:
    any of them
}