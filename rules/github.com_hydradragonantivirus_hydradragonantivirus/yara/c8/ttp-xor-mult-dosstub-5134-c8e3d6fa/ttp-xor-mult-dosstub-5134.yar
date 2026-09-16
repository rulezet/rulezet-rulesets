rule TTP_XOR_MULT_DOSStub_5134 {
  strings:
    $key_5134 = { 05 5c [2] 71 44 [2] 36 46 [2] 71 57 [2] 3f 5b [2] 33 51 [2] 24 5a [2] 3f 14 [2] 02 }

  condition:
    any of them
}