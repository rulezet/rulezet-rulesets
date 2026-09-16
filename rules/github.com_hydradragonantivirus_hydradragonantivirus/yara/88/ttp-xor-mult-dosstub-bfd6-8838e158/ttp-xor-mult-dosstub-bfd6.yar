rule TTP_XOR_MULT_DOSStub_bfd6 {
  strings:
    $key_bfd6 = { eb be [2] 9f a6 [2] d8 a4 [2] 9f b5 [2] d1 b9 [2] dd b3 [2] ca b8 [2] d1 f6 [2] ec }

  condition:
    any of them
}