rule TTP_XOR_MULT_DOSStub_7c74 {
  strings:
    $key_7c74 = { 28 1c [2] 5c 04 [2] 1b 06 [2] 5c 17 [2] 12 1b [2] 1e 11 [2] 09 1a [2] 12 54 [2] 2f }

  condition:
    any of them
}