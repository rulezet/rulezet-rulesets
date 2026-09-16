rule TTP_XOR_MULT_DOSStub_cf80 {
  strings:
    $key_cf80 = { 9b e8 [2] ef f0 [2] a8 f2 [2] ef e3 [2] a1 ef [2] ad e5 [2] ba ee [2] a1 a0 [2] 9c }

  condition:
    any of them
}