rule TTP_XOR_MULT_DOSStub_bfc2 {
  strings:
    $key_bfc2 = { eb aa [2] 9f b2 [2] d8 b0 [2] 9f a1 [2] d1 ad [2] dd a7 [2] ca ac [2] d1 e2 [2] ec }

  condition:
    any of them
}