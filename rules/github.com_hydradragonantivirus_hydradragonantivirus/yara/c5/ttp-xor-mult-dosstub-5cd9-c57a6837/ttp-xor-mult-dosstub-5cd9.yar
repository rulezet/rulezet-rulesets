rule TTP_XOR_MULT_DOSStub_5cd9 {
  strings:
    $key_5cd9 = { 08 b1 [2] 7c a9 [2] 3b ab [2] 7c ba [2] 32 b6 [2] 3e bc [2] 29 b7 [2] 32 f9 [2] 0f }

  condition:
    any of them
}