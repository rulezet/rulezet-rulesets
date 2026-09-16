rule TTP_XOR_MULT_DOSStub_2bc7 {
  strings:
    $key_2bc7 = { 7f af [2] 0b b7 [2] 4c b5 [2] 0b a4 [2] 45 a8 [2] 49 a2 [2] 5e a9 [2] 45 e7 [2] 78 }

  condition:
    any of them
}