rule TTP_XOR_MULT_DOSStub_2860 {
  strings:
    $key_2860 = { 7c 08 [2] 08 10 [2] 4f 12 [2] 08 03 [2] 46 0f [2] 4a 05 [2] 5d 0e [2] 46 40 [2] 7b }

  condition:
    any of them
}