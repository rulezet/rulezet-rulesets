rule TTP_XOR_MULT_DOSStub_bfc6 {
  strings:
    $key_bfc6 = { eb ae [2] 9f b6 [2] d8 b4 [2] 9f a5 [2] d1 a9 [2] dd a3 [2] ca a8 [2] d1 e6 [2] ec }

  condition:
    any of them
}