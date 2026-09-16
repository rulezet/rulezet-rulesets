rule TTP_XOR_MULT_DOSStub_c3ad {
  strings:
    $key_c3ad = { 97 c5 [2] e3 dd [2] a4 df [2] e3 ce [2] ad c2 [2] a1 c8 [2] b6 c3 [2] ad 8d [2] 90 }

  condition:
    any of them
}