rule TTP_XOR_MULT_DOSStub_6234 {
  strings:
    $key_6234 = { 36 5c [2] 42 44 [2] 05 46 [2] 42 57 [2] 0c 5b [2] 00 51 [2] 17 5a [2] 0c 14 [2] 31 }

  condition:
    any of them
}