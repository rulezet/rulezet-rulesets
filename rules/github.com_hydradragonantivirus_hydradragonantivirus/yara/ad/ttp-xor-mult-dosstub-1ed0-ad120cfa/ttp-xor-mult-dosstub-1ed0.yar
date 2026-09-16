rule TTP_XOR_MULT_DOSStub_1ed0 {
  strings:
    $key_1ed0 = { 4a b8 [2] 3e a0 [2] 79 a2 [2] 3e b3 [2] 70 bf [2] 7c b5 [2] 6b be [2] 70 f0 [2] 4d }

  condition:
    any of them
}