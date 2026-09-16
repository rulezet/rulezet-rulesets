rule TTP_XOR_MULT_DOSStub_28f1 {
  strings:
    $key_28f1 = { 7c 99 [2] 08 81 [2] 4f 83 [2] 08 92 [2] 46 9e [2] 4a 94 [2] 5d 9f [2] 46 d1 [2] 7b }

  condition:
    any of them
}