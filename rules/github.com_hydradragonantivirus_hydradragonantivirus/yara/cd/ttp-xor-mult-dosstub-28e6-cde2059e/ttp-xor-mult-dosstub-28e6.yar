rule TTP_XOR_MULT_DOSStub_28e6 {
  strings:
    $key_28e6 = { 7c 8e [2] 08 96 [2] 4f 94 [2] 08 85 [2] 46 89 [2] 4a 83 [2] 5d 88 [2] 46 c6 [2] 7b }

  condition:
    any of them
}