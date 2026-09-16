rule TTP_XOR_MULT_DOSStub_e8c8 {
  strings:
    $key_e8c8 = { bc a0 [2] c8 b8 [2] 8f ba [2] c8 ab [2] 86 a7 [2] 8a ad [2] 9d a6 [2] 86 e8 [2] bb }

  condition:
    any of them
}