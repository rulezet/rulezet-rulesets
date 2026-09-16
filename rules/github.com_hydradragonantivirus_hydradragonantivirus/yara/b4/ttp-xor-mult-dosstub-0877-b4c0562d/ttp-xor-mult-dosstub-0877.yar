rule TTP_XOR_MULT_DOSStub_0877 {
  strings:
    $key_0877 = { 5c 1f [2] 28 07 [2] 6f 05 [2] 28 14 [2] 66 18 [2] 6a 12 [2] 7d 19 [2] 66 57 [2] 5b }

  condition:
    any of them
}