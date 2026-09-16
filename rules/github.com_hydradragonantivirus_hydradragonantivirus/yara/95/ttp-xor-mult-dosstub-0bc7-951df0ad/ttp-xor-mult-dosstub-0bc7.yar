rule TTP_XOR_MULT_DOSStub_0bc7 {
  strings:
    $key_0bc7 = { 5f af [2] 2b b7 [2] 6c b5 [2] 2b a4 [2] 65 a8 [2] 69 a2 [2] 7e a9 [2] 65 e7 [2] 58 }

  condition:
    any of them
}