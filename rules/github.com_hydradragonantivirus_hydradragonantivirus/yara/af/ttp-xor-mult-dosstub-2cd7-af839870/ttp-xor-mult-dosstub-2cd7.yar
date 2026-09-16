rule TTP_XOR_MULT_DOSStub_2cd7 {
  strings:
    $key_2cd7 = { 78 bf [2] 0c a7 [2] 4b a5 [2] 0c b4 [2] 42 b8 [2] 4e b2 [2] 59 b9 [2] 42 f7 [2] 7f }

  condition:
    any of them
}