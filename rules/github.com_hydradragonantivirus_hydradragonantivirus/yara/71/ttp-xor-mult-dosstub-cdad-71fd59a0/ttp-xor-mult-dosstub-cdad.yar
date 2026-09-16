rule TTP_XOR_MULT_DOSStub_cdad {
  strings:
    $key_cdad = { 99 c5 [2] ed dd [2] aa df [2] ed ce [2] a3 c2 [2] af c8 [2] b8 c3 [2] a3 8d [2] 9e }

  condition:
    any of them
}