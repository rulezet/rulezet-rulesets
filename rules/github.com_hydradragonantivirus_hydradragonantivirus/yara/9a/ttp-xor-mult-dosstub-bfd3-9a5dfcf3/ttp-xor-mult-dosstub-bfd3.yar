rule TTP_XOR_MULT_DOSStub_bfd3 {
  strings:
    $key_bfd3 = { eb bb [2] 9f a3 [2] d8 a1 [2] 9f b0 [2] d1 bc [2] dd b6 [2] ca bd [2] d1 f3 [2] ec }

  condition:
    any of them
}