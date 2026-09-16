rule TTP_XOR_MULT_DOSStub_7a32 {
  strings:
    $key_7a32 = { 2e 5a [2] 5a 42 [2] 1d 40 [2] 5a 51 [2] 14 5d [2] 18 57 [2] 0f 5c [2] 14 12 [2] 29 }

  condition:
    any of them
}