rule TTP_XOR_MULT_DOSStub_fbb1 {
  strings:
    $key_fbb1 = { af d9 [2] db c1 [2] 9c c3 [2] db d2 [2] 95 de [2] 99 d4 [2] 8e df [2] 95 91 [2] a8 }

  condition:
    any of them
}