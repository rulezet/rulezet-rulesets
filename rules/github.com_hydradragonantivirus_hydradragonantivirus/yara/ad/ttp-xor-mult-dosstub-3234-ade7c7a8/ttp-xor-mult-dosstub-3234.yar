rule TTP_XOR_MULT_DOSStub_3234 {
  strings:
    $key_3234 = { 66 5c [2] 12 44 [2] 55 46 [2] 12 57 [2] 5c 5b [2] 50 51 [2] 47 5a [2] 5c 14 [2] 61 }

  condition:
    any of them
}