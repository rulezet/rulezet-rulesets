rule TTP_XOR_MULT_DOSStub_5cd7 {
  strings:
    $key_5cd7 = { 08 bf [2] 7c a7 [2] 3b a5 [2] 7c b4 [2] 32 b8 [2] 3e b2 [2] 29 b9 [2] 32 f7 [2] 0f }

  condition:
    any of them
}