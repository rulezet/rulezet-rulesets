rule TTP_XOR_MULT_DOSStub_bfc4 {
  strings:
    $key_bfc4 = { eb ac [2] 9f b4 [2] d8 b6 [2] 9f a7 [2] d1 ab [2] dd a1 [2] ca aa [2] d1 e4 [2] ec }

  condition:
    any of them
}