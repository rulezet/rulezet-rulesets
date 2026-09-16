rule TTP_XOR_MULT_DOSStub_5c08 {
  strings:
    $key_5c08 = { 08 60 [2] 7c 78 [2] 3b 7a [2] 7c 6b [2] 32 67 [2] 3e 6d [2] 29 66 [2] 32 28 [2] 0f }

  condition:
    any of them
}