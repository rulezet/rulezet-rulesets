rule TTP_XOR_MULT_DOSStub_40f5 {
  strings:
    $key_40f5 = { 14 9d [2] 60 85 [2] 27 87 [2] 60 96 [2] 2e 9a [2] 22 90 [2] 35 9b [2] 2e d5 [2] 13 }

  condition:
    any of them
}