rule TTP_XOR_MULT_DOSStub_6232 {
  strings:
    $key_6232 = { 36 5a [2] 42 42 [2] 05 40 [2] 42 51 [2] 0c 5d [2] 00 57 [2] 17 5c [2] 0c 12 [2] 31 }

  condition:
    any of them
}