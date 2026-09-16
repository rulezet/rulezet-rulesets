rule TTP_XOR_MULT_DOSStub_4d32 {
  strings:
    $key_4d32 = { 19 5a [2] 6d 42 [2] 2a 40 [2] 6d 51 [2] 23 5d [2] 2f 57 [2] 38 5c [2] 23 12 [2] 1e }

  condition:
    any of them
}