rule TTP_XOR_MULT_DOSStub_cdb5 {
  strings:
    $key_cdb5 = { 99 dd [2] ed c5 [2] aa c7 [2] ed d6 [2] a3 da [2] af d0 [2] b8 db [2] a3 95 [2] 9e }

  condition:
    any of them
}