rule TTP_XOR_MULT_DOSStub_2820 {
  strings:
    $key_2820 = { 7c 48 [2] 08 50 [2] 4f 52 [2] 08 43 [2] 46 4f [2] 4a 45 [2] 5d 4e [2] 46 00 [2] 7b }

  condition:
    any of them
}