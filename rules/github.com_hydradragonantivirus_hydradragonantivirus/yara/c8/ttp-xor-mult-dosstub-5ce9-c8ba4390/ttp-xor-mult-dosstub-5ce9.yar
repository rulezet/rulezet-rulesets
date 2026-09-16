rule TTP_XOR_MULT_DOSStub_5ce9 {
  strings:
    $key_5ce9 = { 08 81 [2] 7c 99 [2] 3b 9b [2] 7c 8a [2] 32 86 [2] 3e 8c [2] 29 87 [2] 32 c9 [2] 0f }

  condition:
    any of them
}