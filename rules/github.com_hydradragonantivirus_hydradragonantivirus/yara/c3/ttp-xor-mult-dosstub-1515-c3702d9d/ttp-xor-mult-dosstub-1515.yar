rule TTP_XOR_MULT_DOSStub_1515 {
  strings:
    $key_1515 = { 41 7d [2] 35 65 [2] 72 67 [2] 35 76 [2] 7b 7a [2] 77 70 [2] 60 7b [2] 7b 35 [2] 46 }

  condition:
    any of them
}