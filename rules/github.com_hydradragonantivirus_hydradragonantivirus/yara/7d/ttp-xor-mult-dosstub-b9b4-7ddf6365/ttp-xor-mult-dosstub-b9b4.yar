rule TTP_XOR_MULT_DOSStub_b9b4 {
  strings:
    $key_b9b4 = { ed dc [2] 99 c4 [2] de c6 [2] 99 d7 [2] d7 db [2] db d1 [2] cc da [2] d7 94 [2] ea }

  condition:
    any of them
}