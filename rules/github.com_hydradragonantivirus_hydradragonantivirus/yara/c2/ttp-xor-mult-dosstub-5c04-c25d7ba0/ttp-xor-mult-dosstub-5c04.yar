rule TTP_XOR_MULT_DOSStub_5c04 {
  strings:
    $key_5c04 = { 08 6c [2] 7c 74 [2] 3b 76 [2] 7c 67 [2] 32 6b [2] 3e 61 [2] 29 6a [2] 32 24 [2] 0f }

  condition:
    any of them
}