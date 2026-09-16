rule TTP_XOR_MULT_DOSStub_4c32 {
  strings:
    $key_4c32 = { 18 5a [2] 6c 42 [2] 2b 40 [2] 6c 51 [2] 22 5d [2] 2e 57 [2] 39 5c [2] 22 12 [2] 1f }

  condition:
    any of them
}