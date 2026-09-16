rule TTP_XOR_MULT_DOSStub_3877 {
  strings:
    $key_3877 = { 6c 1f [2] 18 07 [2] 5f 05 [2] 18 14 [2] 56 18 [2] 5a 12 [2] 4d 19 [2] 56 57 [2] 6b }

  condition:
    any of them
}