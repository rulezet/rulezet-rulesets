rule TTP_XOR_MULT_DOSStub_dcad {
  strings:
    $key_dcad = { 88 c5 [2] fc dd [2] bb df [2] fc ce [2] b2 c2 [2] be c8 [2] a9 c3 [2] b2 8d [2] 8f }

  condition:
    any of them
}