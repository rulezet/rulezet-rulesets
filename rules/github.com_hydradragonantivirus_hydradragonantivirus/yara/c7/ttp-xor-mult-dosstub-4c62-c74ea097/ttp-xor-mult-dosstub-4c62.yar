rule TTP_XOR_MULT_DOSStub_4c62 {
  strings:
    $key_4c62 = { 18 0a [2] 6c 12 [2] 2b 10 [2] 6c 01 [2] 22 0d [2] 2e 07 [2] 39 0c [2] 22 42 [2] 1f }

  condition:
    any of them
}