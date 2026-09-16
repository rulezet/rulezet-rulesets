rule TTP_XOR_MULT_DOSStub_ee87 {
  strings:
    $key_ee87 = { ba ef [2] ce f7 [2] 89 f5 [2] ce e4 [2] 80 e8 [2] 8c e2 [2] 9b e9 [2] 80 a7 [2] bd }

  condition:
    any of them
}