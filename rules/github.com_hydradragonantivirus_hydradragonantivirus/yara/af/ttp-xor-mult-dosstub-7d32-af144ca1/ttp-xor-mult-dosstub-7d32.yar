rule TTP_XOR_MULT_DOSStub_7d32 {
  strings:
    $key_7d32 = { 29 5a [2] 5d 42 [2] 1a 40 [2] 5d 51 [2] 13 5d [2] 1f 57 [2] 08 5c [2] 13 12 [2] 2e }

  condition:
    any of them
}