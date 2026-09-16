rule TTP_XOR_MULT_DOSStub_1427 {
  strings:
    $key_1427 = { 40 4f [2] 34 57 [2] 73 55 [2] 34 44 [2] 7a 48 [2] 76 42 [2] 61 49 [2] 7a 07 [2] 47 }

  condition:
    any of them
}