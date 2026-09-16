rule TTP_XOR_MULT_DOSStub_7c69 {
  strings:
    $key_7c69 = { 28 01 [2] 5c 19 [2] 1b 1b [2] 5c 0a [2] 12 06 [2] 1e 0c [2] 09 07 [2] 12 49 [2] 2f }

  condition:
    any of them
}