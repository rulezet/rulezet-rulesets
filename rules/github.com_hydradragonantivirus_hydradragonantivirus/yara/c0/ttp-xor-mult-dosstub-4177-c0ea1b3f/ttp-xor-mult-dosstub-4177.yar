rule TTP_XOR_MULT_DOSStub_4177 {
  strings:
    $key_4177 = { 15 1f [2] 61 07 [2] 26 05 [2] 61 14 [2] 2f 18 [2] 23 12 [2] 34 19 [2] 2f 57 [2] 12 }

  condition:
    any of them
}