rule TTP_XOR_MULT_DOSStub_bfd1 {
  strings:
    $key_bfd1 = { eb b9 [2] 9f a1 [2] d8 a3 [2] 9f b2 [2] d1 be [2] dd b4 [2] ca bf [2] d1 f1 [2] ec }

  condition:
    any of them
}