rule TTP_XOR_MULT_DOSStub_bfc5 {
  strings:
    $key_bfc5 = { eb ad [2] 9f b5 [2] d8 b7 [2] 9f a6 [2] d1 aa [2] dd a0 [2] ca ab [2] d1 e5 [2] ec }

  condition:
    any of them
}