rule TTP_XOR_MULT_DOSStub_cf87 {
  strings:
    $key_cf87 = { 9b ef [2] ef f7 [2] a8 f5 [2] ef e4 [2] a1 e8 [2] ad e2 [2] ba e9 [2] a1 a7 [2] 9c }

  condition:
    any of them
}