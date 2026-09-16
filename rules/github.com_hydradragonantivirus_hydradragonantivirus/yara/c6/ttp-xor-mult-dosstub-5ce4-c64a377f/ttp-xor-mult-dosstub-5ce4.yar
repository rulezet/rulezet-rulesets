rule TTP_XOR_MULT_DOSStub_5ce4 {
  strings:
    $key_5ce4 = { 08 8c [2] 7c 94 [2] 3b 96 [2] 7c 87 [2] 32 8b [2] 3e 81 [2] 29 8a [2] 32 c4 [2] 0f }

  condition:
    any of them
}