rule TTP_XOR_MULT_DOSStub_cf8d {
  strings:
    $key_cf8d = { 9b e5 [2] ef fd [2] a8 ff [2] ef ee [2] a1 e2 [2] ad e8 [2] ba e3 [2] a1 ad [2] 9c }

  condition:
    any of them
}