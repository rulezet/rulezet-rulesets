rule TTP_XOR_MULT_DOSStub_4ce4 {
  strings:
    $key_4ce4 = { 18 8c [2] 6c 94 [2] 2b 96 [2] 6c 87 [2] 22 8b [2] 2e 81 [2] 39 8a [2] 22 c4 [2] 1f }

  condition:
    any of them
}