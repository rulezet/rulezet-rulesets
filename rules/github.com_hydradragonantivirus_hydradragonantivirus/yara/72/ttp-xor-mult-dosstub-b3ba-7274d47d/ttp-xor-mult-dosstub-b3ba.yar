rule TTP_XOR_MULT_DOSStub_b3ba {
  strings:
    $key_b3ba = { e7 d2 [2] 93 ca [2] d4 c8 [2] 93 d9 [2] dd d5 [2] d1 df [2] c6 d4 [2] dd 9a [2] e0 }

  condition:
    any of them
}