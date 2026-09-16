rule TTP_XOR_MULT_DOSStub_7c19 {
  strings:
    $key_7c19 = { 28 71 [2] 5c 69 [2] 1b 6b [2] 5c 7a [2] 12 76 [2] 1e 7c [2] 09 77 [2] 12 39 [2] 2f }

  condition:
    any of them
}