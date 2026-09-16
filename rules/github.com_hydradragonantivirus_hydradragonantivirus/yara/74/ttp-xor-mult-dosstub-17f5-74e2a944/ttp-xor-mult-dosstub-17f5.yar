rule TTP_XOR_MULT_DOSStub_17f5 {
  strings:
    $key_17f5 = { 43 9d [2] 37 85 [2] 70 87 [2] 37 96 [2] 79 9a [2] 75 90 [2] 62 9b [2] 79 d5 [2] 44 }

  condition:
    any of them
}