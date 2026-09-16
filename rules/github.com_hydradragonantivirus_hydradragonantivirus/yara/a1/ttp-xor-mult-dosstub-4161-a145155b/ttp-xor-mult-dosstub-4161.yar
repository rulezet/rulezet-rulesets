rule TTP_XOR_MULT_DOSStub_4161 {
  strings:
    $key_4161 = { 15 09 [2] 61 11 [2] 26 13 [2] 61 02 [2] 2f 0e [2] 23 04 [2] 34 0f [2] 2f 41 [2] 12 }

  condition:
    any of them
}