rule TTP_XOR_MULT_DOSStub_2856 {
  strings:
    $key_2856 = { 7c 3e [2] 08 26 [2] 4f 24 [2] 08 35 [2] 46 39 [2] 4a 33 [2] 5d 38 [2] 46 76 [2] 7b }

  condition:
    any of them
}