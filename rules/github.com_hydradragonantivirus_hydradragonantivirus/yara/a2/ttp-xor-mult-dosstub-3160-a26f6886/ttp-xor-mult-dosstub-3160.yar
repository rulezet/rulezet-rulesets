rule TTP_XOR_MULT_DOSStub_3160 {
  strings:
    $key_3160 = { 65 08 [2] 11 10 [2] 56 12 [2] 11 03 [2] 5f 0f [2] 53 05 [2] 44 0e [2] 5f 40 [2] 62 }

  condition:
    any of them
}