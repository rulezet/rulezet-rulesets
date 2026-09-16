rule TTP_XOR_MULT_DOSStub_1437 {
  strings:
    $key_1437 = { 40 5f [2] 34 47 [2] 73 45 [2] 34 54 [2] 7a 58 [2] 76 52 [2] 61 59 [2] 7a 17 [2] 47 }

  condition:
    any of them
}