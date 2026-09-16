rule TTP_XOR_MULT_DOSStub_3615 {
  strings:
    $key_3615 = { 62 7d [2] 16 65 [2] 51 67 [2] 16 76 [2] 58 7a [2] 54 70 [2] 43 7b [2] 58 35 [2] 65 }

  condition:
    any of them
}