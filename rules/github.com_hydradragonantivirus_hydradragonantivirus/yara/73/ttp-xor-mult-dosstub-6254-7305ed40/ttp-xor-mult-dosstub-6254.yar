rule TTP_XOR_MULT_DOSStub_6254 {
  strings:
    $key_6254 = { 36 3c [2] 42 24 [2] 05 26 [2] 42 37 [2] 0c 3b [2] 00 31 [2] 17 3a [2] 0c 74 [2] 31 }

  condition:
    any of them
}