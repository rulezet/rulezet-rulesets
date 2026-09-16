rule TTP_XOR_MULT_DOSStub_5634 {
  strings:
    $key_5634 = { 02 5c [2] 76 44 [2] 31 46 [2] 76 57 [2] 38 5b [2] 34 51 [2] 23 5a [2] 38 14 [2] 05 }

  condition:
    any of them
}