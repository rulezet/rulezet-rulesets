rule TTP_XOR_MULT_DOSStub_5c14 {
  strings:
    $key_5c14 = { 08 7c [2] 7c 64 [2] 3b 66 [2] 7c 77 [2] 32 7b [2] 3e 71 [2] 29 7a [2] 32 34 [2] 0f }

  condition:
    any of them
}