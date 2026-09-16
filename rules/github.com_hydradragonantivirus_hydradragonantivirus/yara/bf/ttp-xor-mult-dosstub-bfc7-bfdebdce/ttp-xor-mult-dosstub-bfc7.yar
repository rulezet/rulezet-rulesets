rule TTP_XOR_MULT_DOSStub_bfc7 {
  strings:
    $key_bfc7 = { eb af [2] 9f b7 [2] d8 b5 [2] 9f a4 [2] d1 a8 [2] dd a2 [2] ca a9 [2] d1 e7 [2] ec }

  condition:
    any of them
}