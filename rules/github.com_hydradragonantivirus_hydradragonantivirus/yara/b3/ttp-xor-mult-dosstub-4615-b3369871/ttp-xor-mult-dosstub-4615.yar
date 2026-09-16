rule TTP_XOR_MULT_DOSStub_4615 {
  strings:
    $key_4615 = { 12 7d [2] 66 65 [2] 21 67 [2] 66 76 [2] 28 7a [2] 24 70 [2] 33 7b [2] 28 35 [2] 15 }

  condition:
    any of them
}