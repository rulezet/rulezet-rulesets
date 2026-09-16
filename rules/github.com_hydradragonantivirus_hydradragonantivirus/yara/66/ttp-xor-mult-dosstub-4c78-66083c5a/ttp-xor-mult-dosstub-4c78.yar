rule TTP_XOR_MULT_DOSStub_4c78 {
  strings:
    $key_4c78 = { 18 10 [2] 6c 08 [2] 2b 0a [2] 6c 1b [2] 22 17 [2] 2e 1d [2] 39 16 [2] 22 58 [2] 1f }

  condition:
    any of them
}