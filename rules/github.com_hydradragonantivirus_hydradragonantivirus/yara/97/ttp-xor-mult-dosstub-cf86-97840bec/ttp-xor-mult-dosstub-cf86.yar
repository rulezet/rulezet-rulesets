rule TTP_XOR_MULT_DOSStub_cf86 {
  strings:
    $key_cf86 = { 9b ee [2] ef f6 [2] a8 f4 [2] ef e5 [2] a1 e9 [2] ad e3 [2] ba e8 [2] a1 a6 [2] 9c }

  condition:
    any of them
}