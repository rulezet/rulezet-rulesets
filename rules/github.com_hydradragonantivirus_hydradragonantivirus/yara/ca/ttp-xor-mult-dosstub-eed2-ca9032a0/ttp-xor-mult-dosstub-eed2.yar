rule TTP_XOR_MULT_DOSStub_eed2 {
  strings:
    $key_eed2 = { ba ba [2] ce a2 [2] 89 a0 [2] ce b1 [2] 80 bd [2] 8c b7 [2] 9b bc [2] 80 f2 [2] bd }

  condition:
    any of them
}