rule TTP_XOR_MULT_DOSStub_3166 {
  strings:
    $key_3166 = { 65 0e [2] 11 16 [2] 56 14 [2] 11 05 [2] 5f 09 [2] 53 03 [2] 44 08 [2] 5f 46 [2] 62 }

  condition:
    any of them
}