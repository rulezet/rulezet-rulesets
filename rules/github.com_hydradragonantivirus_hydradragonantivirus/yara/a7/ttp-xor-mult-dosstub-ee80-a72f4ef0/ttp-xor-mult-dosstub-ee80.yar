rule TTP_XOR_MULT_DOSStub_ee80 {
  strings:
    $key_ee80 = { ba e8 [2] ce f0 [2] 89 f2 [2] ce e3 [2] 80 ef [2] 8c e5 [2] 9b ee [2] 80 a0 [2] bd }

  condition:
    any of them
}