rule TTP_XOR_MULT_DOSStub_eed7 {
  strings:
    $key_eed7 = { ba bf [2] ce a7 [2] 89 a5 [2] ce b4 [2] 80 b8 [2] 8c b2 [2] 9b b9 [2] 80 f7 [2] bd }

  condition:
    any of them
}