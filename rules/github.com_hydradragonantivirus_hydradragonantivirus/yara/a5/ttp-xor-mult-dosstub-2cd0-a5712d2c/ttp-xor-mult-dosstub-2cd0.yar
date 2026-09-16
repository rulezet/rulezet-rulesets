rule TTP_XOR_MULT_DOSStub_2cd0 {
  strings:
    $key_2cd0 = { 78 b8 [2] 0c a0 [2] 4b a2 [2] 0c b3 [2] 42 bf [2] 4e b5 [2] 59 be [2] 42 f0 [2] 7f }

  condition:
    any of them
}