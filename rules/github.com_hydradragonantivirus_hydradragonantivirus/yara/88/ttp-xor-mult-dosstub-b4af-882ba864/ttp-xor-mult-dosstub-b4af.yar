rule TTP_XOR_MULT_DOSStub_b4af {
  strings:
    $key_b4af = { e0 c7 [2] 94 df [2] d3 dd [2] 94 cc [2] da c0 [2] d6 ca [2] c1 c1 [2] da 8f [2] e7 }

  condition:
    any of them
}