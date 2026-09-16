rule TTP_XOR_MULT_DOSStub_7c32 {
  strings:
    $key_7c32 = { 28 5a [2] 5c 42 [2] 1b 40 [2] 5c 51 [2] 12 5d [2] 1e 57 [2] 09 5c [2] 12 12 [2] 2f }

  condition:
    any of them
}