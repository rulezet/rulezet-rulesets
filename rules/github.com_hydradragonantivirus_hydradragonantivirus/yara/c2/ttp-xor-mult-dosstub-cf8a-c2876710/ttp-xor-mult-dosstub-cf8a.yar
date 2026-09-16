rule TTP_XOR_MULT_DOSStub_cf8a {
  strings:
    $key_cf8a = { 9b e2 [2] ef fa [2] a8 f8 [2] ef e9 [2] a1 e5 [2] ad ef [2] ba e4 [2] a1 aa [2] 9c }

  condition:
    any of them
}