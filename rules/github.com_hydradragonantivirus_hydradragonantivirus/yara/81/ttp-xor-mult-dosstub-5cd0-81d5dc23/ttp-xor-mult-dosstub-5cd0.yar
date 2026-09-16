rule TTP_XOR_MULT_DOSStub_5cd0 {
  strings:
    $key_5cd0 = { 08 b8 [2] 7c a0 [2] 3b a2 [2] 7c b3 [2] 32 bf [2] 3e b5 [2] 29 be [2] 32 f0 [2] 0f }

  condition:
    any of them
}