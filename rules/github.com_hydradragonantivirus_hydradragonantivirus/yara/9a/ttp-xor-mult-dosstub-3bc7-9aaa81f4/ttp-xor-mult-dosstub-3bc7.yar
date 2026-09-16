rule TTP_XOR_MULT_DOSStub_3bc7 {
  strings:
    $key_3bc7 = { 6f af [2] 1b b7 [2] 5c b5 [2] 1b a4 [2] 55 a8 [2] 59 a2 [2] 4e a9 [2] 55 e7 [2] 68 }

  condition:
    any of them
}