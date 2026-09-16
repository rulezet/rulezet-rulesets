rule TTP_XOR_MULT_DOSStub_1715 {
  strings:
    $key_1715 = { 43 7d [2] 37 65 [2] 70 67 [2] 37 76 [2] 79 7a [2] 75 70 [2] 62 7b [2] 79 35 [2] 44 }

  condition:
    any of them
}