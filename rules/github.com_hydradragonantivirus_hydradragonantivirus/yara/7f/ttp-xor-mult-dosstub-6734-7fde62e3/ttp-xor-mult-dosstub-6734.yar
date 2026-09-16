rule TTP_XOR_MULT_DOSStub_6734 {
  strings:
    $key_6734 = { 33 5c [2] 47 44 [2] 00 46 [2] 47 57 [2] 09 5b [2] 05 51 [2] 12 5a [2] 09 14 [2] 34 }

  condition:
    any of them
}