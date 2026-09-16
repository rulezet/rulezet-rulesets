rule TTP_XOR_MULT_DOSStub_7c78 {
  strings:
    $key_7c78 = { 28 10 [2] 5c 08 [2] 1b 0a [2] 5c 1b [2] 12 17 [2] 1e 1d [2] 09 16 [2] 12 58 [2] 2f }

  condition:
    any of them
}