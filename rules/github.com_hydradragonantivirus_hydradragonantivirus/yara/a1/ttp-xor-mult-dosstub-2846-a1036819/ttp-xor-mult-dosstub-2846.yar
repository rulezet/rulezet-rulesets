rule TTP_XOR_MULT_DOSStub_2846 {
  strings:
    $key_2846 = { 7c 2e [2] 08 36 [2] 4f 34 [2] 08 25 [2] 46 29 [2] 4a 23 [2] 5d 28 [2] 46 66 [2] 7b }

  condition:
    any of them
}