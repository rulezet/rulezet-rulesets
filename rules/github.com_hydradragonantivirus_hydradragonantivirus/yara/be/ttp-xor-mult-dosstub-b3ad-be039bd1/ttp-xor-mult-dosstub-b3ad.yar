rule TTP_XOR_MULT_DOSStub_b3ad {
  strings:
    $key_b3ad = { e7 c5 [2] 93 dd [2] d4 df [2] 93 ce [2] dd c2 [2] d1 c8 [2] c6 c3 [2] dd 8d [2] e0 }

  condition:
    any of them
}