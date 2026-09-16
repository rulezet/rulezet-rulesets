rule TTP_XOR_MULT_DOSStub_b3af {
  strings:
    $key_b3af = { e7 c7 [2] 93 df [2] d4 dd [2] 93 cc [2] dd c0 [2] d1 ca [2] c6 c1 [2] dd 8f [2] e0 }

  condition:
    any of them
}