rule TTP_XOR_MULT_DOSStub_1877 {
  strings:
    $key_1877 = { 4c 1f [2] 38 07 [2] 7f 05 [2] 38 14 [2] 76 18 [2] 7a 12 [2] 6d 19 [2] 76 57 [2] 4b }

  condition:
    any of them
}