rule TTP_XOR_MULT_DOSStub_1867 {
  strings:
    $key_1867 = { 4c 0f [2] 38 17 [2] 7f 15 [2] 38 04 [2] 76 08 [2] 7a 02 [2] 6d 09 [2] 76 47 [2] 4b }

  condition:
    any of them
}