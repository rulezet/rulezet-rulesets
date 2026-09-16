rule TTP_XOR_MULT_DOSStub_dfad {
  strings:
    $key_dfad = { 8b c5 [2] ff dd [2] b8 df [2] ff ce [2] b1 c2 [2] bd c8 [2] aa c3 [2] b1 8d [2] 8c }

  condition:
    any of them
}