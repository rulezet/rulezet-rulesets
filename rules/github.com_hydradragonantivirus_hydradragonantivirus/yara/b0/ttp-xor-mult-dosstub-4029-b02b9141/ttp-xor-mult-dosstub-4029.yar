rule TTP_XOR_MULT_DOSStub_4029 {
  strings:
    $key_4029 = { 14 41 [2] 60 59 [2] 27 5b [2] 60 4a [2] 2e 46 [2] 22 4c [2] 35 47 [2] 2e 09 [2] 13 }

  condition:
    any of them
}