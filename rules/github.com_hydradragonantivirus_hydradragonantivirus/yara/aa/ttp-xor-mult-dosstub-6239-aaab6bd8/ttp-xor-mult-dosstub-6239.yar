rule TTP_XOR_MULT_DOSStub_6239 {
  strings:
    $key_6239 = { 36 51 [2] 42 49 [2] 05 4b [2] 42 5a [2] 0c 56 [2] 00 5c [2] 17 57 [2] 0c 19 [2] 31 }

  condition:
    any of them
}