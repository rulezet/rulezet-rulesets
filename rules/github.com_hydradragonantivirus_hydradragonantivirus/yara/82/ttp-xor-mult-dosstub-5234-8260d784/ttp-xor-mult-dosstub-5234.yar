rule TTP_XOR_MULT_DOSStub_5234 {
  strings:
    $key_5234 = { 06 5c [2] 72 44 [2] 35 46 [2] 72 57 [2] 3c 5b [2] 30 51 [2] 27 5a [2] 3c 14 [2] 01 }

  condition:
    any of them
}