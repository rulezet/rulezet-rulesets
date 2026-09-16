rule TTP_XOR_MULT_DOSStub_1462 {
  strings:
    $key_1462 = { 40 0a [2] 34 12 [2] 73 10 [2] 34 01 [2] 7a 0d [2] 76 07 [2] 61 0c [2] 7a 42 [2] 47 }

  condition:
    any of them
}