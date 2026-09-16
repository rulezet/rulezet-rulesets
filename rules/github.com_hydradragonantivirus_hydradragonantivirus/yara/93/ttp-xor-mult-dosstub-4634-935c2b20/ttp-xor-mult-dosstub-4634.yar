rule TTP_XOR_MULT_DOSStub_4634 {
  strings:
    $key_4634 = { 12 5c [2] 66 44 [2] 21 46 [2] 66 57 [2] 28 5b [2] 24 51 [2] 33 5a [2] 28 14 [2] 15 }

  condition:
    any of them
}