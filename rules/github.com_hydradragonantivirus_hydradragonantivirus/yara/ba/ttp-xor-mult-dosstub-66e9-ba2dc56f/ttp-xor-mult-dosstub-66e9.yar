rule TTP_XOR_MULT_DOSStub_66e9 {
  strings:
    $key_66e9 = { 32 81 [2] 46 99 [2] 01 9b [2] 46 8a [2] 08 86 [2] 04 8c [2] 13 87 [2] 08 c9 [2] 35 }

  condition:
    any of them
}