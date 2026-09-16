rule TTP_XOR_MULT_DOSStub_bfd0 {
  strings:
    $key_bfd0 = { eb b8 [2] 9f a0 [2] d8 a2 [2] 9f b3 [2] d1 bf [2] dd b5 [2] ca be [2] d1 f0 [2] ec }

  condition:
    any of them
}