rule TTP_XOR_MULT_DOSStub_bfd2 {
  strings:
    $key_bfd2 = { eb ba [2] 9f a2 [2] d8 a0 [2] 9f b1 [2] d1 bd [2] dd b7 [2] ca bc [2] d1 f2 [2] ec }

  condition:
    any of them
}