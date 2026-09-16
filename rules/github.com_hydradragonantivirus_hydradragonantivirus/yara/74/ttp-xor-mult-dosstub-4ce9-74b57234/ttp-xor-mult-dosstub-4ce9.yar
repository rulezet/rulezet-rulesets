rule TTP_XOR_MULT_DOSStub_4ce9 {
  strings:
    $key_4ce9 = { 18 81 [2] 6c 99 [2] 2b 9b [2] 6c 8a [2] 22 86 [2] 2e 8c [2] 39 87 [2] 22 c9 [2] 1f }

  condition:
    any of them
}