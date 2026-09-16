rule TTP_XOR_MULT_DOSStub_5d32 {
  strings:
    $key_5d32 = { 09 5a [2] 7d 42 [2] 3a 40 [2] 7d 51 [2] 33 5d [2] 3f 57 [2] 28 5c [2] 33 12 [2] 0e }

  condition:
    any of them
}