rule TTP_XOR_MULT_DOSStub_4054 {
  strings:
    $key_4054 = { 14 3c [2] 60 24 [2] 27 26 [2] 60 37 [2] 2e 3b [2] 22 31 [2] 35 3a [2] 2e 74 [2] 13 }

  condition:
    any of them
}