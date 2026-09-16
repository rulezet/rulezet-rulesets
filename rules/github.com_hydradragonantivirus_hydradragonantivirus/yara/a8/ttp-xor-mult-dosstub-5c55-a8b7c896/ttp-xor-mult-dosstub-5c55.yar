rule TTP_XOR_MULT_DOSStub_5c55 {
  strings:
    $key_5c55 = { 08 3d [2] 7c 25 [2] 3b 27 [2] 7c 36 [2] 32 3a [2] 3e 30 [2] 29 3b [2] 32 75 [2] 0f }

  condition:
    any of them
}