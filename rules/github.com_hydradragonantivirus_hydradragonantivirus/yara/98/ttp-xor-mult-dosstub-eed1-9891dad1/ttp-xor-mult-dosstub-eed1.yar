rule TTP_XOR_MULT_DOSStub_eed1 {
  strings:
    $key_eed1 = { ba b9 [2] ce a1 [2] 89 a3 [2] ce b2 [2] 80 be [2] 8c b4 [2] 9b bf [2] 80 f1 [2] bd }

  condition:
    any of them
}