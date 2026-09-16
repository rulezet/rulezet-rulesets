rule TTP_XOR_MULT_DOSStub_2115 {
  strings:
    $key_2115 = { 75 7d [2] 01 65 [2] 46 67 [2] 01 76 [2] 4f 7a [2] 43 70 [2] 54 7b [2] 4f 35 [2] 72 }

  condition:
    any of them
}