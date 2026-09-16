rule TTP_XOR_MULT_DOSStub_4013 {
  strings:
    $key_4013 = { 14 7b [2] 60 63 [2] 27 61 [2] 60 70 [2] 2e 7c [2] 22 76 [2] 35 7d [2] 2e 33 [2] 13 }

  condition:
    any of them
}