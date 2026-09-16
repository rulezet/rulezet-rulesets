rule TTP_XOR_MULT_DOSStub_fec8 {
  strings:
    $key_fec8 = { aa a0 [2] de b8 [2] 99 ba [2] de ab [2] 90 a7 [2] 9c ad [2] 8b a6 [2] 90 e8 [2] ad }

  condition:
    any of them
}