rule TTP_XOR_MULT_DOSStub_2847 {
  strings:
    $key_2847 = { 7c 2f [2] 08 37 [2] 4f 35 [2] 08 24 [2] 46 28 [2] 4a 22 [2] 5d 29 [2] 46 67 [2] 7b }

  condition:
    any of them
}