rule TTP_XOR_MULT_DOSStub_bfc8 {
  strings:
    $key_bfc8 = { eb a0 [2] 9f b8 [2] d8 ba [2] 9f ab [2] d1 a7 [2] dd ad [2] ca a6 [2] d1 e8 [2] ec }

  condition:
    any of them
}