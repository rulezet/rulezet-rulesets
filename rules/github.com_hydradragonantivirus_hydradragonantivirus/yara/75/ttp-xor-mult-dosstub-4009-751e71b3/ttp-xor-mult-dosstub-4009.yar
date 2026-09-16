rule TTP_XOR_MULT_DOSStub_4009 {
  strings:
    $key_4009 = { 14 61 [2] 60 79 [2] 27 7b [2] 60 6a [2] 2e 66 [2] 22 6c [2] 35 67 [2] 2e 29 [2] 13 }

  condition:
    any of them
}