rule TTP_XOR_MULT_DOSStub_cdb2 {
  strings:
    $key_cdb2 = { 99 da [2] ed c2 [2] aa c0 [2] ed d1 [2] a3 dd [2] af d7 [2] b8 dc [2] a3 92 [2] 9e }

  condition:
    any of them
}