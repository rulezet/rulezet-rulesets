rule TTP_XOR_MULT_DOSStub_66e7 {
  strings:
    $key_66e7 = { 32 8f [2] 46 97 [2] 01 95 [2] 46 84 [2] 08 88 [2] 04 82 [2] 13 89 [2] 08 c7 [2] 35 }

  condition:
    any of them
}