rule TTP_XOR_MULT_DOSStub_7c14 {
  strings:
    $key_7c14 = { 28 7c [2] 5c 64 [2] 1b 66 [2] 5c 77 [2] 12 7b [2] 1e 71 [2] 09 7a [2] 12 34 [2] 2f }

  condition:
    any of them
}