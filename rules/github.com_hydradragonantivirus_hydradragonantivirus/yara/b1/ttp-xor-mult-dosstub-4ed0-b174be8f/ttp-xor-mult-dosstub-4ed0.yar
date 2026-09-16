rule TTP_XOR_MULT_DOSStub_4ed0 {
  strings:
    $key_4ed0 = { 1a b8 [2] 6e a0 [2] 29 a2 [2] 6e b3 [2] 20 bf [2] 2c b5 [2] 3b be [2] 20 f0 [2] 1d }

  condition:
    any of them
}