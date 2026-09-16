rule TTP_XOR_MULT_DOSStub_1839 {
  strings:
    $key_1839 = { 4c 51 [2] 38 49 [2] 7f 4b [2] 38 5a [2] 76 56 [2] 7a 5c [2] 6d 57 [2] 76 19 [2] 4b }

  condition:
    any of them
}