rule TTP_XOR_MULT_DOSStub_cdc8 {
  strings:
    $key_cdc8 = { 99 a0 [2] ed b8 [2] aa ba [2] ed ab [2] a3 a7 [2] af ad [2] b8 a6 [2] a3 e8 [2] 9e }

  condition:
    any of them
}