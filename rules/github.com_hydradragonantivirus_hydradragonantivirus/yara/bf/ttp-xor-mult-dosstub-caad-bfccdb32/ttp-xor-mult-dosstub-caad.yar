rule TTP_XOR_MULT_DOSStub_caad {
  strings:
    $key_caad = { 9e c5 [2] ea dd [2] ad df [2] ea ce [2] a4 c2 [2] a8 c8 [2] bf c3 [2] a4 8d [2] 99 }

  condition:
    any of them
}