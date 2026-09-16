rule TTP_XOR_MULT_DOSStub_b0ba {
  strings:
    $key_b0ba = { e4 d2 [2] 90 ca [2] d7 c8 [2] 90 d9 [2] de d5 [2] d2 df [2] c5 d4 [2] de 9a [2] e3 }

  condition:
    any of them
}