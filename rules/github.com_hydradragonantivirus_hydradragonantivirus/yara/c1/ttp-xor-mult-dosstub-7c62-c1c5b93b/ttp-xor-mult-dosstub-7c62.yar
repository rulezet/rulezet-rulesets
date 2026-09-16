rule TTP_XOR_MULT_DOSStub_7c62 {
  strings:
    $key_7c62 = { 28 0a [2] 5c 12 [2] 1b 10 [2] 5c 01 [2] 12 0d [2] 1e 07 [2] 09 0c [2] 12 42 [2] 2f }

  condition:
    any of them
}