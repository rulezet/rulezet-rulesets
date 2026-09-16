rule TTP_XOR_MULT_DOSStub_b9d9 {
  strings:
    $key_b9d9 = { ed b1 [2] 99 a9 [2] de ab [2] 99 ba [2] d7 b6 [2] db bc [2] cc b7 [2] d7 f9 [2] ea }

  condition:
    any of them
}