rule TTP_XOR_MULT_DOSStub_66f1 {
  strings:
    $key_66f1 = { 32 99 [2] 46 81 [2] 01 83 [2] 46 92 [2] 08 9e [2] 04 94 [2] 13 9f [2] 08 d1 [2] 35 }

  condition:
    any of them
}