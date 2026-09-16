rule TTP_XOR_MULT_DOSStub_66e8 {
  strings:
    $key_66e8 = { 32 80 [2] 46 98 [2] 01 9a [2] 46 8b [2] 08 87 [2] 04 8d [2] 13 86 [2] 08 c8 [2] 35 }

  condition:
    any of them
}