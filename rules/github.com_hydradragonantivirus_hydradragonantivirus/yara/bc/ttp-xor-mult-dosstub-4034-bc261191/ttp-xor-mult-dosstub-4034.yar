rule TTP_XOR_MULT_DOSStub_4034 {
  strings:
    $key_4034 = { 14 5c [2] 60 44 [2] 27 46 [2] 60 57 [2] 2e 5b [2] 22 51 [2] 35 5a [2] 2e 14 [2] 13 }

  condition:
    any of them
}