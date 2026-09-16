rule TTP_XOR_MULT_DOSStub_2ed6 {
  strings:
    $key_2ed6 = { 7a be [2] 0e a6 [2] 49 a4 [2] 0e b5 [2] 40 b9 [2] 4c b3 [2] 5b b8 [2] 40 f6 [2] 7d }

  condition:
    any of them
}