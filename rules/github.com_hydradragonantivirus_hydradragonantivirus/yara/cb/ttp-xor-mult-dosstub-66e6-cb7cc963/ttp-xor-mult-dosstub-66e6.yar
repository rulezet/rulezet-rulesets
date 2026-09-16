rule TTP_XOR_MULT_DOSStub_66e6 {
  strings:
    $key_66e6 = { 32 8e [2] 46 96 [2] 01 94 [2] 46 85 [2] 08 89 [2] 04 83 [2] 13 88 [2] 08 c6 [2] 35 }

  condition:
    any of them
}