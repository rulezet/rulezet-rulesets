rule TTP_XOR_MULT_DOSStub_5637 {
  strings:
    $key_5637 = { 02 5f [2] 76 47 [2] 31 45 [2] 76 54 [2] 38 58 [2] 34 52 [2] 23 59 [2] 38 17 [2] 05 }

  condition:
    any of them
}