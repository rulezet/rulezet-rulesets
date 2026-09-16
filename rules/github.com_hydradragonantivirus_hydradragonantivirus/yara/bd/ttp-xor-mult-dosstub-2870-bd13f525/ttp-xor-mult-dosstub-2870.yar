rule TTP_XOR_MULT_DOSStub_2870 {
  strings:
    $key_2870 = { 7c 18 [2] 08 00 [2] 4f 02 [2] 08 13 [2] 46 1f [2] 4a 15 [2] 5d 1e [2] 46 50 [2] 7b }

  condition:
    any of them
}