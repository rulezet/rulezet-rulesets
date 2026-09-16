rule TTP_XOR_MULT_DOSStub_3cd0 {
  strings:
    $key_3cd0 = { 68 b8 [2] 1c a0 [2] 5b a2 [2] 1c b3 [2] 52 bf [2] 5e b5 [2] 49 be [2] 52 f0 [2] 6f }

  condition:
    any of them
}