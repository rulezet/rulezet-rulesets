rule TTP_XOR_MULT_DOSStub_66e5 {
  strings:
    $key_66e5 = { 32 8d [2] 46 95 [2] 01 97 [2] 46 86 [2] 08 8a [2] 04 80 [2] 13 8b [2] 08 c5 [2] 35 }

  condition:
    any of them
}