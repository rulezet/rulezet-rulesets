rule TTP_XOR_MULT_DOSStub_1827 {
  strings:
    $key_1827 = { 4c 4f [2] 38 57 [2] 7f 55 [2] 38 44 [2] 76 48 [2] 7a 42 [2] 6d 49 [2] 76 07 [2] 4b }

  condition:
    any of them
}