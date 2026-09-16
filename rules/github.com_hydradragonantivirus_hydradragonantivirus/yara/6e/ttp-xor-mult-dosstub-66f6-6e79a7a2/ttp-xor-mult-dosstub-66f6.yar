rule TTP_XOR_MULT_DOSStub_66f6 {
  strings:
    $key_66f6 = { 32 9e [2] 46 86 [2] 01 84 [2] 46 95 [2] 08 99 [2] 04 93 [2] 13 98 [2] 08 d6 [2] 35 }

  condition:
    any of them
}