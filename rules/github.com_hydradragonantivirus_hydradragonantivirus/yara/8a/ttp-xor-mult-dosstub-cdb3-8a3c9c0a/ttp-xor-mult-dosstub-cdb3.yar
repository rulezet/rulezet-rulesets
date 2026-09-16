rule TTP_XOR_MULT_DOSStub_cdb3 {
  strings:
    $key_cdb3 = { 99 db [2] ed c3 [2] aa c1 [2] ed d0 [2] a3 dc [2] af d6 [2] b8 dd [2] a3 93 [2] 9e }

  condition:
    any of them
}