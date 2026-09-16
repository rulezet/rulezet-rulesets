rule TTP_XOR_MULT_DOSStub_2841 {
  strings:
    $key_2841 = { 7c 29 [2] 08 31 [2] 4f 33 [2] 08 22 [2] 46 2e [2] 4a 24 [2] 5d 2f [2] 46 61 [2] 7b }

  condition:
    any of them
}