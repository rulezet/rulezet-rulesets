rule TTP_XOR_MULT_DOSStub_b0ad {
  strings:
    $key_b0ad = { e4 c5 [2] 90 dd [2] d7 df [2] 90 ce [2] de c2 [2] d2 c8 [2] c5 c3 [2] de 8d [2] e3 }

  condition:
    any of them
}