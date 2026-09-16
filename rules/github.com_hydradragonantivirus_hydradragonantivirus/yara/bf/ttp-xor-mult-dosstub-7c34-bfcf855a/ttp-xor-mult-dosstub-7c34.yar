rule TTP_XOR_MULT_DOSStub_7c34 {
  strings:
    $key_7c34 = { 28 5c [2] 5c 44 [2] 1b 46 [2] 5c 57 [2] 12 5b [2] 1e 51 [2] 09 5a [2] 12 14 [2] 2f }

  condition:
    any of them
}