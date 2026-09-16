rule TTP_XOR_MULT_DOSStub_5c58 {
  strings:
    $key_5c58 = { 08 30 [2] 7c 28 [2] 3b 2a [2] 7c 3b [2] 32 37 [2] 3e 3d [2] 29 36 [2] 32 78 [2] 0f }

  condition:
    any of them
}