rule TTP_XOR_MULT_DOSStub_2ed0 {
  strings:
    $key_2ed0 = { 7a b8 [2] 0e a0 [2] 49 a2 [2] 0e b3 [2] 40 bf [2] 4c b5 [2] 5b be [2] 40 f0 [2] 7d }

  condition:
    any of them
}